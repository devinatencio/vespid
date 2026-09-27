from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

# ── Counter snapshot helpers ─────────────────────────────────────────────


def insert_counter_snapshots(
    conn: sqlite3.Connection,
    node_id: str,
    timestamp: str,
    counters: list[dict],
) -> int:
    """Bulk-insert counter snapshot rows from a heartbeat payload.

    Each counter dict in the payload is expected to have at least a ``set``
    key (the nftables set name) and integer ``packets`` and ``bytes`` values.
    Entries missing the ``set`` key or with non-integer ``packets``/``bytes``
    values are skipped with a warning log.

    Args:
        conn: An open SQLite connection.
        node_id: The reporting node's identifier.
        timestamp: ISO-8601 UTC timestamp from the heartbeat.
        counters: A list of counter dicts from the heartbeat payload.
            Expected keys: ``set``, ``chain``, ``family``, ``packets``,
            ``bytes``.

    Returns:
        The number of rows inserted.
    """
    if not counters:
        return 0

    sql = (
        "INSERT INTO counter_snapshots "
        "(node_id, timestamp, set_name, chain, family, packets, bytes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)"
    )

    rows = []
    for entry in counters:
        # Skip entries missing the required 'set' key
        if not isinstance(entry, dict) or "set" not in entry:
            logger.warning("Skipping malformed counter entry (missing 'set'): %r", entry)
            continue

        # Validate packets and bytes are integers
        packets = entry.get("packets", 0)
        bytes_val = entry.get("bytes", 0)

        try:
            packets = int(packets)
        except (TypeError, ValueError):
            logger.warning("Skipping counter entry with non-integer 'packets': %r", entry)
            continue

        try:
            bytes_val = int(bytes_val)
        except (TypeError, ValueError):
            logger.warning("Skipping counter entry with non-integer 'bytes': %r", entry)
            continue

        rows.append(
            (
                node_id,
                timestamp,
                entry["set"],
                entry.get("chain", ""),
                entry.get("family", ""),
                packets,
                bytes_val,
            )
        )

    if rows:
        conn.executemany(sql, rows)
        conn.commit()

    return len(rows)


def compute_deltas(snapshots: list[dict]) -> list[dict]:
    """Compute deltas from ordered snapshots for a single (node_id, set_name).

    When the current cumulative value is less than the previous value, a
    counter reset is assumed (e.g. service restart). Reset points are
    marked with is_reset=True and their delta is set to 0 because the
    true traffic volume during the gap is unknown. This prevents restart
    spikes from distorting the chart.

    Args:
        snapshots: A list of snapshot dicts ordered by timestamp ASC.
            Each dict must contain keys: ``timestamp``, ``packets``, ``bytes``.

    Returns:
        A list of dicts with keys: ``timestamp``, ``delta_packets``,
        ``delta_bytes``, ``is_reset``. The first element always has
        delta values of 0 and is_reset False.
    """
    results = []
    for i, snap in enumerate(snapshots):
        if i == 0:
            results.append(
                {
                    "timestamp": snap["timestamp"],
                    "delta_packets": 0,
                    "delta_bytes": 0,
                    "is_reset": False,
                }
            )
        else:
            prev = snapshots[i - 1]
            is_reset = snap["packets"] < prev["packets"]
            if is_reset:
                # Counter reset detected — we can't know the real delta
                # across the restart gap, so report 0 to avoid chart spikes.
                delta_p = 0
                delta_b = 0
            else:
                delta_p = snap["packets"] - prev["packets"]
                delta_b = snap["bytes"] - prev["bytes"]
            results.append(
                {
                    "timestamp": snap["timestamp"],
                    "delta_packets": delta_p,
                    "delta_bytes": delta_b,
                    "is_reset": is_reset,
                }
            )
    return results


def _friendly_set_name_plain(raw_name: str) -> str:
    """Convert an nftables set name into a human-readable label without emoji.

    Examples:
        shield_feed_firehol_level1  → Firehol Level1
        shield_feed_abuse_ch_feodo  → Abuse Ch Feodo
        shield_local_blocks         → Local Blocks
        shield_local                → Local Blocks
        some_other_set              → Some Other Set
    """
    display = raw_name
    if display.startswith("shield_feed_"):
        display = display[len("shield_feed_") :]
    elif display.startswith("shield_local"):
        display = display[len("shield_local") :]
        if display.startswith("_"):
            display = display[1:]
        if not display:
            display = "Local Blocks"
    # Replace underscores with spaces and title-case each word
    display = display.replace("_", " ").strip().title()
    return display


# Time range mapping for counter history queries
_COUNTER_HISTORY_RANGES = {
    "1h": {"hours": 1},
    "6h": {"hours": 6},
    "24h": {"hours": 24},
    "7d": {"days": 7},
}


def get_counter_history(
    conn: sqlite3.Connection,
    time_range: str,
    node_id: str | None = None,
) -> dict:
    """Return time-series delta data for counter history charts.

    Queries counter_snapshots within the specified time window, groups by
    (node_id, set_name), computes deltas for each group, and returns a
    structured response suitable for Chart.js rendering.

    When node_id is None, deltas are aggregated (summed) across all nodes
    for each (set_name, timestamp) pair. When node_id is specified, only
    that node's data is returned.

    Args:
        conn: An open SQLite connection.
        time_range: One of '1h', '6h', '24h', '7d'.
        node_id: Optional node filter. None means aggregate all nodes.

    Returns:
        A dict with keys:
            - labels: list of ISO-8601 timestamp strings
            - datasets: list of dicts with 'label', 'data', 'resets' keys
            - lifetime_totals: dict mapping set label to total delta sum
    """
    from datetime import timedelta

    range_config = _COUNTER_HISTORY_RANGES.get(time_range)
    if range_config is None:
        return {"labels": [], "datasets": [], "lifetime_totals": {}}

    now = datetime.now(UTC)
    cutoff = now - timedelta(**range_config)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Query snapshots within the time window PLUS the last snapshot before
    # the cutoff for each (node_id, set_name) group. This "lookback" row
    # provides the baseline so the first in-window delta is meaningful
    # instead of always being 0.
    if node_id is not None:
        rows = conn.execute(
            "SELECT node_id, set_name, timestamp, packets, bytes "
            "FROM counter_snapshots "
            "WHERE timestamp >= ? AND node_id = ? "
            "ORDER BY node_id, set_name, timestamp ASC",
            (cutoff_str, node_id),
        ).fetchall()
        # Fetch the last snapshot before the cutoff per (node_id, set_name)
        lookback_rows = conn.execute(
            "SELECT cs.node_id, cs.set_name, cs.timestamp, cs.packets, cs.bytes "
            "FROM counter_snapshots cs "
            "INNER JOIN ("
            "  SELECT node_id, set_name, MAX(timestamp) AS max_ts "
            "  FROM counter_snapshots "
            "  WHERE timestamp < ? AND node_id = ? "
            "  GROUP BY node_id, set_name"
            ") latest ON cs.node_id = latest.node_id "
            "  AND cs.set_name = latest.set_name "
            "  AND cs.timestamp = latest.max_ts",
            (cutoff_str, node_id),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT node_id, set_name, timestamp, packets, bytes "
            "FROM counter_snapshots "
            "WHERE timestamp >= ? "
            "ORDER BY node_id, set_name, timestamp ASC",
            (cutoff_str,),
        ).fetchall()
        # Fetch the last snapshot before the cutoff per (node_id, set_name)
        lookback_rows = conn.execute(
            "SELECT cs.node_id, cs.set_name, cs.timestamp, cs.packets, cs.bytes "
            "FROM counter_snapshots cs "
            "INNER JOIN ("
            "  SELECT node_id, set_name, MAX(timestamp) AS max_ts "
            "  FROM counter_snapshots "
            "  WHERE timestamp < ? "
            "  GROUP BY node_id, set_name"
            ") latest ON cs.node_id = latest.node_id "
            "  AND cs.set_name = latest.set_name "
            "  AND cs.timestamp = latest.max_ts",
            (cutoff_str,),
        ).fetchall()

    if not rows:
        return {"labels": [], "datasets": [], "lifetime_totals": {}}

    # Group by (node_id, set_name) and compute deltas per group
    from collections import defaultdict

    # First, aggregate by (node_id, set_name, timestamp) to handle
    # multiple rows per timestamp (e.g., same set in multiple chains).
    # We sum packets/bytes across chains for the same (node, set, ts).
    raw_groups: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)

    # Include lookback rows first (they provide the baseline for first delta)
    for row in lookback_rows:
        key = (row["node_id"], row["set_name"])
        ts = row["timestamp"]
        if ts not in raw_groups[key]:
            raw_groups[key][ts] = {"packets": 0, "bytes": 0}
        raw_groups[key][ts]["packets"] += row["packets"]
        raw_groups[key][ts]["bytes"] += row["bytes"]

    # Then include the in-window rows
    for row in rows:
        key = (row["node_id"], row["set_name"])
        ts = row["timestamp"]
        if ts not in raw_groups[key]:
            raw_groups[key][ts] = {"packets": 0, "bytes": 0}
        raw_groups[key][ts]["packets"] += row["packets"]
        raw_groups[key][ts]["bytes"] += row["bytes"]

    # Convert to sorted list of snapshots per group
    groups: dict[tuple[str, str], list[dict]] = {}
    for key, ts_map in raw_groups.items():
        groups[key] = [
            {"timestamp": ts, "packets": vals["packets"], "bytes": vals["bytes"]}
            for ts, vals in sorted(ts_map.items())
        ]

    # Compute deltas for each (node_id, set_name) group
    # Then aggregate by (set_name, timestamp)
    # Structure: {set_name: {timestamp: {"delta_packets": int, "is_reset": bool}}}
    aggregated: dict[str, dict[str, dict]] = defaultdict(
        lambda: defaultdict(lambda: {"delta_packets": 0, "is_reset": False})
    )

    # Track which timestamps came from lookback (before cutoff) so we can
    # exclude them from the final chart labels while still using them for
    # delta computation.
    lookback_timestamps: set[str] = set()
    for row in lookback_rows:
        lookback_timestamps.add(row["timestamp"])

    for (_nid, set_name), snapshots in groups.items():
        deltas = compute_deltas(snapshots)
        for d in deltas:
            ts = d["timestamp"]
            # Skip lookback timestamps from the output — they only serve
            # as a baseline for computing the first in-window delta.
            if ts in lookback_timestamps and ts < cutoff_str:
                continue
            aggregated[set_name][ts]["delta_packets"] += d["delta_packets"]
            if d["is_reset"]:
                aggregated[set_name][ts]["is_reset"] = True

    # Collect all unique timestamps across all sets, sorted
    all_timestamps: set[str] = set()
    for ts_map in aggregated.values():
        all_timestamps.update(ts_map.keys())
    labels = sorted(all_timestamps)

    # Build datasets and lifetime_totals
    datasets = []
    lifetime_totals = {}

    for set_name in sorted(aggregated.keys()):
        friendly_name = _friendly_set_name_plain(set_name)
        ts_map = aggregated[set_name]

        data = []
        resets = []
        total = 0

        for ts in labels:
            entry = ts_map.get(ts)
            if entry is not None:
                data.append(entry["delta_packets"])
                resets.append(entry["is_reset"])
                total += entry["delta_packets"]
            else:
                data.append(0)
                resets.append(False)

        datasets.append(
            {
                "label": friendly_name,
                "data": data,
                "resets": resets,
            }
        )
        lifetime_totals[friendly_name] = total

    return {
        "labels": labels,
        "datasets": datasets,
        "lifetime_totals": lifetime_totals,
    }


def cleanup_counter_snapshots(
    conn: sqlite3.Connection,
    retention_days: int = 30,
) -> int:
    """Delete counter snapshot rows older than the retention period.

    Computes a cutoff timestamp as ``retention_days`` days before the
    current UTC time and removes all rows with a timestamp earlier than
    that cutoff.

    Args:
        conn: An open SQLite connection.
        retention_days: Number of days of history to retain. Rows older
            than this are deleted. Defaults to 30.

    Returns:
        The number of deleted rows.
    """
    from datetime import timedelta

    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    cursor = conn.execute(
        "DELETE FROM counter_snapshots WHERE timestamp < ?",
        (cutoff_str,),
    )
    conn.commit()
    return cursor.rowcount

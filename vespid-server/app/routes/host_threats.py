"""Host Threats blueprint — Kill Chain Timeline, Score Sparkline, and Summary Cards.

Provides API endpoints for the host threat dashboard panels and renders
the Host Threat Timeline and Process Tree visualization pages.

Endpoints:
    GET /admin/host-threats                  — Host Threat Timeline page (paginated table)
    GET /admin/host-threats/process-tree     — Process Tree visualization page
    GET /admin/host-threats/timeline         — Kill Chain Timeline JSON (Chart.js scatter)
    GET /admin/host-threats/score-history    — 24h score timeseries JSON (288 points)
    GET /admin/host-threats/summary          — Per-host summary cards JSON

Requirements: 8.7, 8.8, 8.9
"""

import json
import logging
import math
import smtplib
from datetime import UTC, datetime, timedelta
from email.mime.text import MIMEText

import requests
from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import login_required

from app.config_resolution import resolve_effective_profile
from app.default_noise_rules import is_default_noise
from app.models import create_command, get_db

logger = logging.getLogger(__name__)

host_threats_bp = Blueprint(
    "host_threats",
    __name__,
    template_folder="templates",
)

# ── ATT&CK Tactic Color Mapping ─────────────────────────────────────────────
# Maps Sigma rule tag prefixes to human-readable tactic names and Chart.js colors.

TACTIC_MAP = {
    "attack.initial_access": ("Initial Access", "#3B82F6"),
    "attack.execution": ("Execution", "#F97316"),
    "attack.persistence": ("Persistence", "#EF4444"),
    "attack.privilege_escalation": ("Privilege Escalation", "#DC2626"),
    "attack.defense_evasion": ("Defense Evasion", "#EAB308"),
    "attack.credential_access": ("Credential Access", "#8B5CF6"),
    "attack.lateral_movement": ("Lateral Movement", "#7C3AED"),
    "attack.command_and_control": ("Command and Control", "#991B1B"),
    "attack.exfiltration": ("Exfiltration", "#EC4899"),
}

# Default for untagged or unrecognized rules
_DEFAULT_TACTIC = ("Unknown", "#6B7280")

# Default scoring parameters (matching agent-side HostScorer defaults)
_DEFAULT_HALF_LIFE = 28800  # seconds (8 hours)
_DEFAULT_THRESHOLD = 100

# Severity weight mapping (rule event_type → weight)
_SEVERITY_WEIGHTS = {
    "critical": 50,
    "high": 25,
    "medium": 10,
    "low": 5,
    "informational": 1,
}

# Numeric weight → human severity name (reverse of _SEVERITY_WEIGHTS)
_SEVERITY_NAMES = {w: name for name, w in _SEVERITY_WEIGHTS.items()}


def _get_severity_weight(event_type: str) -> int:
    """Map an event_type string to its severity weight."""
    lower = event_type.lower() if event_type else ""
    for key, weight in _SEVERITY_WEIGHTS.items():
        if key in lower:
            return weight
    return 10  # default to medium


def _get_severity_name(weight) -> str:
    """Map a severity weight to its human-readable name."""
    try:
        return _SEVERITY_NAMES.get(int(weight), "warning")
    except (ValueError, TypeError):
        return "warning"


def _extract_tactic(tags_json: str) -> tuple[str, str, str]:
    """Extract the first ATT&CK tactic from a rule's tags JSON.

    Returns (tactic_key, tactic_name, color).
    """
    try:
        tags = json.loads(tags_json) if tags_json else []
    except (json.JSONDecodeError, TypeError):
        tags = []

    for tag in tags:
        tag_lower = tag.lower().strip()
        if tag_lower in TACTIC_MAP:
            name, color = TACTIC_MAP[tag_lower]
            return tag_lower, name, color

    return "unknown", _DEFAULT_TACTIC[0], _DEFAULT_TACTIC[1]


def _iso_to_epoch(ts_str: str) -> float:
    """Convert an ISO-8601 timestamp string to epoch seconds."""
    try:
        # Handle various ISO formats
        ts_str = ts_str.strip()
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0


def _apply_suppression(events: list[dict], profile: dict | None) -> list[dict]:
    """Filter and group events based on profile suppression config.

    Applies three suppression mechanisms in order:
    1. suppress_rules — completely remove events whose rule_name is in the list
    2. group_rules — collapse repeated firings of the same rule within 5-minute
       windows into a single event with a ``grouped_count`` field
    3. threshold_rules — hide events for rules that haven't fired at least
       ``min_count`` times within the configured ``window_minutes``

    Args:
        events: List of event dicts, each containing at least ``rule_name``
            and ``timestamp`` keys.
        profile: A profile dict (as returned by ``resolve_effective_profile``)
            containing a ``settings`` key with JSON string, or None.

    Returns:
        A new list of event dicts after suppression is applied.
    """
    if not events:
        return []

    # Parse profile settings
    suppress_rules: list[str] = []
    group_rules: list[str] = []
    threshold_rules: dict[str, dict] = {}

    if profile is not None:
        settings_raw = profile.get("settings")
        if settings_raw is not None:
            try:
                if isinstance(settings_raw, str):
                    settings = json.loads(settings_raw)
                elif isinstance(settings_raw, dict):
                    settings = settings_raw
                else:
                    settings = {}
            except (json.JSONDecodeError, TypeError):
                logger.warning("Malformed profile settings JSON, skipping suppression")
                settings = {}
        else:
            settings = {}

        # Extract suppress_rules — filter to valid strings only
        raw_suppress = settings.get("suppress_rules")
        if isinstance(raw_suppress, list):
            suppress_rules = [r for r in raw_suppress if isinstance(r, str)]

        # Disabled rules should also be hidden from dashboard panels.
        # A rule that is disabled on the agent (never evaluated) has no
        # reason to show its historical events either.
        raw_disabled = settings.get("disabled_host_threat_rules")
        if isinstance(raw_disabled, list):
            disabled_rules = [r for r in raw_disabled if isinstance(r, str)]
            suppress_rules = list(set(suppress_rules) | set(disabled_rules))

        # Extract group_rules — filter to valid strings only
        raw_group = settings.get("group_rules")
        if isinstance(raw_group, list):
            group_rules = [r for r in raw_group if isinstance(r, str)]

        # Extract threshold_rules — validate structure
        raw_threshold = settings.get("threshold_rules")
        if isinstance(raw_threshold, dict):
            for rule_name, config in raw_threshold.items():
                if not isinstance(rule_name, str):
                    continue
                if isinstance(config, dict):
                    min_count = config.get("min_count")
                    window_minutes = config.get("window_minutes")
                    if isinstance(min_count, (int, float)) and isinstance(
                        window_minutes, (int, float)
                    ):
                        threshold_rules[rule_name] = {
                            "min_count": int(min_count),
                            "window_minutes": int(window_minutes),
                        }

    # Step 1: Remove suppressed rules
    if suppress_rules:
        suppress_set = set(suppress_rules)
        events = [e for e in events if e.get("rule_name") not in suppress_set]

    # Step 2: Group rules — collapse within 5-minute windows
    if group_rules:
        group_set = set(group_rules)
        grouped_events = []
        non_grouped_events = []

        for e in events:
            if e.get("rule_name") in group_set:
                grouped_events.append(e)
            else:
                non_grouped_events.append(e)

        # For each rule in group_rules, collapse events within 5-min windows
        collapsed = []
        # Group by rule_name first
        by_rule: dict[str, list[dict]] = {}
        for e in grouped_events:
            rn = e.get("rule_name", "")
            if rn not in by_rule:
                by_rule[rn] = []
            by_rule[rn].append(e)

        window_seconds = 300  # 5 minutes

        for _rule_name, rule_events in by_rule.items():
            # Sort by timestamp
            rule_events.sort(key=lambda e: _iso_to_epoch(e.get("timestamp", "")))

            if not rule_events:
                continue

            # Walk through events, creating windows
            window_start_epoch = _iso_to_epoch(rule_events[0].get("timestamp", ""))
            window_events = [rule_events[0]]

            for e in rule_events[1:]:
                e_epoch = _iso_to_epoch(e.get("timestamp", ""))
                if e_epoch - window_start_epoch <= window_seconds:
                    # Same window
                    window_events.append(e)
                else:
                    # Emit the collapsed event for the previous window
                    representative = dict(window_events[0])
                    representative["grouped_count"] = len(window_events)
                    collapsed.append(representative)
                    # Start new window
                    window_start_epoch = e_epoch
                    window_events = [e]

            # Emit the last window
            representative = dict(window_events[0])
            representative["grouped_count"] = len(window_events)
            collapsed.append(representative)

        # Merge back: non-grouped + collapsed, preserving relative order by timestamp
        events = non_grouped_events + collapsed
        events.sort(key=lambda e: _iso_to_epoch(e.get("timestamp", "")))

    # Step 3: Threshold rules — only show rules that meet minimum firing count
    if threshold_rules:
        threshold_set = set(threshold_rules.keys())
        non_threshold_events = []
        threshold_events: dict[str, list[dict]] = {}

        for e in events:
            rn = e.get("rule_name", "")
            if rn in threshold_set:
                if rn not in threshold_events:
                    threshold_events[rn] = []
                threshold_events[rn].append(e)
            else:
                non_threshold_events.append(e)

        passing_events = []
        for rule_name, rule_evts in threshold_events.items():
            config = threshold_rules[rule_name]
            min_count = config["min_count"]
            window_minutes = config["window_minutes"]
            window_seconds = window_minutes * 60

            # Sort events by timestamp
            rule_evts.sort(key=lambda e: _iso_to_epoch(e.get("timestamp", "")))

            # For each event, count how many events of this rule are within
            # the window ending at that event's timestamp. If count >= min_count,
            # include all events from that window.
            # Simpler approach: use sliding windows from the first event.
            # We check each window of window_minutes duration and if the count
            # within that window meets min_count, we include those events.
            if not rule_evts:
                continue

            included_indices: set[int] = set()

            # Walk through with a sliding window
            for _i, e in enumerate(rule_evts):
                e_epoch = _iso_to_epoch(e.get("timestamp", ""))
                # Count events within [e_epoch - window_seconds, e_epoch]
                count = 0
                for _j, other in enumerate(rule_evts):
                    other_epoch = _iso_to_epoch(other.get("timestamp", ""))
                    if e_epoch - window_seconds <= other_epoch <= e_epoch:
                        count += 1
                if count >= min_count:
                    # Include all events in this window
                    for j, other in enumerate(rule_evts):
                        other_epoch = _iso_to_epoch(other.get("timestamp", ""))
                        if e_epoch - window_seconds <= other_epoch <= e_epoch:
                            included_indices.add(j)

            for idx in sorted(included_indices):
                passing_events.append(rule_evts[idx])

        events = non_threshold_events + passing_events
        events.sort(key=lambda e: _iso_to_epoch(e.get("timestamp", "")))

    return events


# ── Page Routes ──────────────────────────────────────────────────────────────


@host_threats_bp.route("/admin/host-threats")
@login_required
def host_threats_page():
    """Render the unified Host Threats Dashboard page.

    Queries distinct hostnames from host_events to populate the global
    hostname filter dropdown in the template.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        hostname_rows = db.execute(
            "SELECT DISTINCT hostname FROM host_events ORDER BY hostname"
        ).fetchall()
        hostnames = [r["hostname"] for r in hostname_rows]
    finally:
        db.close()

    return render_template(
        "admin/host_threats_dashboard.html",
        hostnames=hostnames,
    )


@host_threats_bp.route("/admin/host-threats/host/<hostname>")
@login_required
def host_threat_detail(hostname):
    """Render a dedicated page for a single host's threat data.

    Verifies the hostname exists in host_events, then renders a standalone
    page with kill chain, score sparkline, events table, and noise analysis
    for just this host.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        row = db.execute(
            "SELECT 1 FROM host_events WHERE hostname = ? LIMIT 1",
            (hostname,),
        ).fetchone()
        if not row:
            return render_template(
                "admin/host_threat_detail.html", hostname=hostname, not_found=True
            )
    finally:
        db.close()

    return render_template(
        "admin/host_threat_detail.html",
        hostname=hostname,
        not_found=False,
    )


def _build_process_tree(db, hostname, limit=500):
    """Build a deduplicated process tree from host_events for a given hostname.

    For each distinct PID, the most recent event (by timestamp) is used so that
    duplicate pid entries from multiple audit log lines don't overwrite children.
    Returns (tree, truncated) where tree is a list of root nodes sorted by
    timestamp descending, and truncated is True when the node limit was hit.
    """
    rows = db.execute(
        "SELECT DISTINCT h.pid, h.ppid, h.exe, h.command_line, h.timestamp "
        "FROM host_events h "
        "INNER JOIN ("
        "  SELECT pid, MAX(timestamp) AS max_ts "
        "  FROM host_events "
        "  WHERE hostname = ? "
        "  GROUP BY pid"
        ") latest ON h.pid = latest.pid AND h.timestamp = latest.max_ts "
        "WHERE h.hostname = ? "
        "ORDER BY h.timestamp DESC "
        "LIMIT ?",
        (hostname, hostname, limit),
    ).fetchall()

    truncated = len(rows) >= limit

    nodes = {}
    for r in rows:
        nodes[r["pid"]] = {
            "pid": r["pid"],
            "ppid": r["ppid"],
            "exe": r["exe"],
            "command_line": r["command_line"],
            "timestamp": r["timestamp"],
            "children": [],
        }

    roots = []
    for _pid, node in nodes.items():
        ppid = node["ppid"]
        if ppid in nodes and ppid != _pid:
            nodes[ppid]["children"].append(node)
        else:
            roots.append(node)

    for node in nodes.values():
        node["children"].sort(key=lambda c: c.get("timestamp", ""), reverse=True)

    roots.sort(key=lambda n: n.get("timestamp", ""), reverse=True)

    return roots, truncated


def _count_tree_nodes(roots):
    """Count total nodes in a process tree (roots + all descendants)."""
    total = 0
    stack = list(roots)
    while stack:
        node = stack.pop()
        total += 1
        stack.extend(node.get("children", []))
    return total


@host_threats_bp.route("/admin/host-threats/process-tree")
@login_required
def process_tree_page():
    """Render the Process Tree visualization page (full page or HTMX fragment)."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        hostname_rows = db.execute(
            "SELECT DISTINCT hostname FROM host_events ORDER BY hostname"
        ).fetchall()
        hostnames = [r["hostname"] for r in hostname_rows]

        selected_hostname = request.args.get("hostname", "")
        tree = []
        truncated = False

        if selected_hostname:
            tree, truncated = _build_process_tree(db, selected_hostname)
        node_count = _count_tree_nodes(tree)
    finally:
        db.close()

    if request.headers.get("HX-Request"):
        return render_template(
            "admin/host_threats/_process_tree_fragment.html",
            hostnames=hostnames,
            selected_hostname=selected_hostname,
            tree=tree,
            truncated=truncated,
            node_count=node_count,
        )

    return render_template(
        "admin/host_process_tree.html",
        hostnames=hostnames,
        selected_hostname=selected_hostname,
        tree=tree,
        truncated=truncated,
        node_count=node_count,
    )


# ── API Endpoints ────────────────────────────────────────────────────────────


@host_threats_bp.route("/admin/host-threats/timeline")
@login_required
def kill_chain_timeline():
    """Return host events grouped by ATT&CK tactic for Chart.js rendering.

    Query params:
        hostname: Filter by hostname (optional)
        hours: Time window in hours (default 24)
        max_events: Maximum events to return (default 2000)

    Returns JSON formatted for Chart.js scatter dataset:
    {
        "datasets": [
            {
                "label": "Execution",
                "backgroundColor": "#F97316",
                "borderColor": "#F97316",
                "data": [{"x": "2024-01-15T10:30:00Z", "y": 1, "meta": {...}}]
            },
            ...
        ],
        "tactics": ["Initial Access", "Execution", ...]
    }
    """
    hostname = request.args.get("hostname", "")
    hours = request.args.get("hours", 24, type=int)
    max_events = request.args.get("max_events", 2000, type=int)

    # Compute time boundary
    now = datetime.now(UTC)
    since = now - timedelta(hours=hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Query host_events within time window, capped at max_events
        if hostname:
            rows = db.execute(
                "SELECT he.timestamp, he.hostname, he.rule_name, he.exe, he.command_line, he.event_type "
                "FROM host_events he "
                "WHERE he.hostname = ? AND he.timestamp >= ? "
                "ORDER BY he.timestamp ASC "
                "LIMIT ?",
                (hostname, since_iso, max_events),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT he.timestamp, he.hostname, he.rule_name, he.exe, he.command_line, he.event_type "
                "FROM host_events he "
                "WHERE he.timestamp >= ? "
                "ORDER BY he.timestamp ASC "
                "LIMIT ?",
                (since_iso, max_events),
            ).fetchall()

        # Look up rule tags from detection_rules_custom for tactic mapping
        rule_names = list({r["rule_name"] for r in rows})
        rule_tags = {}
        if rule_names:
            placeholders = ",".join(["?"] * len(rule_names))
            tag_rows = db.execute(
                f"SELECT name, tags FROM detection_rules_custom WHERE name IN ({placeholders})",
                rule_names,
            ).fetchall()
            for tr in tag_rows:
                rule_tags[tr["name"]] = tr["tags"]

    finally:
        db.close()

    # Apply suppression filtering when scoped to a single host
    if hostname:
        db = get_db(db_path)
        try:
            node_row = db.execute(
                "SELECT node_id FROM host_events WHERE hostname = ? LIMIT 1",
                (hostname,),
            ).fetchone()
            node_id = node_row["node_id"] if node_row else ""
            profile = resolve_effective_profile(db, node_id) if node_id else None
            rows = _apply_suppression([dict(r) for r in rows], profile)
        finally:
            db.close()

    # Group events by tactic
    tactic_datasets = {}  # tactic_key -> list of data points
    tactic_order = list(TACTIC_MAP.keys()) + ["unknown"]

    for row in rows:
        tags_json = rule_tags.get(row["rule_name"], "[]")
        tactic_key, tactic_name, color = _extract_tactic(tags_json)

        if tactic_key not in tactic_datasets:
            tactic_datasets[tactic_key] = {
                "label": tactic_name,
                "backgroundColor": color,
                "borderColor": color,
                "data": [],
                "pointRadius": 5,
            }

        # Y-axis position is the tactic index
        y_index = (
            tactic_order.index(tactic_key) if tactic_key in tactic_order else len(tactic_order)
        )

        tactic_datasets[tactic_key]["data"].append(
            {
                "x": row["timestamp"],
                "y": y_index,
                "meta": {
                    "hostname": row["hostname"],
                    "rule_name": row["rule_name"],
                    "exe": row["exe"],
                    "command_line": row["command_line"][:120],
                },
            }
        )

    # Build ordered datasets list
    datasets = []
    for key in tactic_order:
        if key in tactic_datasets:
            datasets.append(tactic_datasets[key])

    # Build tactic labels for Y-axis
    tactic_labels = []
    for key in tactic_order:
        if key in TACTIC_MAP:
            tactic_labels.append(TACTIC_MAP[key][0])
        elif key == "unknown":
            tactic_labels.append(_DEFAULT_TACTIC[0])

    return jsonify(
        {
            "datasets": datasets,
            "tactics": tactic_labels,
        }
    )


@host_threats_bp.route("/admin/host-threats/score-history")
@login_required
def score_history():
    """Return score timeseries (288 points) for a given hostname.

    Query params:
        hostname: The host to compute scores for (optional; empty returns
            an empty series so the dashboard can render a "select a host"
            empty state instead of an error)
        hours: Time window in hours, clamped to 1..168 (default 24)
        half_life: Decay half-life in seconds (default _DEFAULT_HALF_LIFE)
        threshold: Alert threshold (default 100)

    Returns JSON:
    {
        "labels": ["2024-01-15T10:00:00Z", ...],
        "scores": [0.0, 12.5, ...],
        "threshold": 100,
        "hostname": "web-01",
        "hours": 24
    }

    The score at each sample point is computed using the exponential decay formula:
        effective_score = sum(weight_i * 2^(-(t_sample - t_event) / half_life))
    for all events with t_event <= t_sample.
    """
    hostname = request.args.get("hostname", "")
    half_life = request.args.get("half_life", _DEFAULT_HALF_LIFE, type=float)
    threshold = request.args.get("threshold", _DEFAULT_THRESHOLD, type=float)
    hours = request.args.get("hours", 24, type=int)
    hours = max(1, min(hours, 168))  # clamp to 1h..7d

    if not hostname:
        return jsonify(
            {
                "labels": [],
                "scores": [],
                "threshold": threshold,
                "hostname": "",
                "hours": hours,
            }
        ), 200

    # Time range: past `hours` hours, 288 sample points evenly spaced.
    # Divide by (num_points - 1) so the final sample lands exactly on `now`;
    # otherwise the last point lags one interval behind (5 min at 24h, 35 min
    # at 7d) and a recent score rise is missing from the chart tail.
    now = datetime.now(UTC)
    start = now - timedelta(hours=hours)
    num_points = 288
    interval = timedelta(hours=hours) / (num_points - 1)

    start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        import time as _time

        _t0 = _time.time()
        # Fetch all host events for this hostname in the past 24h
        rows = db.execute(
            "SELECT timestamp, event_type, rule_name FROM host_events "
            "WHERE hostname = ? AND timestamp >= ? "
            "ORDER BY timestamp ASC",
            (hostname, start_iso),
        ).fetchall()
        _t1 = _time.time()
        logger.info(
            "score-history: query returned %d rows in %.3fs for host=%s",
            len(rows),
            _t1 - _t0,
            hostname,
        )

        # Resolve effective profile for suppression
        node_row = db.execute(
            "SELECT node_id FROM host_events WHERE hostname = ? LIMIT 1",
            (hostname,),
        ).fetchone()
        node_id = node_row["node_id"] if node_row else ""
        profile = resolve_effective_profile(db, node_id) if node_id else None
    finally:
        db.close()

    # Convert rows to dicts for suppression filtering
    events_raw = [dict(r) for r in rows]

    # Apply suppression filtering
    filtered_events = _apply_suppression(events_raw, profile)

    # Pre-process filtered events into (epoch, weight) pairs
    contributions = []
    for ev in filtered_events:
        t_event = _iso_to_epoch(ev["timestamp"])
        weight = _get_severity_weight(ev["event_type"])
        contributions.append((t_event, weight))

    # Compute score at each of the 288 sample points using INCREMENTAL approach.
    # Key insight: score(t+dt) = score(t) * decay_factor + new_events_in_interval
    # This is O(events + num_points) instead of O(events * num_points).
    labels = []
    scores = []
    start_epoch = start.timestamp()
    interval_secs = interval.total_seconds()
    decay_rate = math.log(2) / half_life
    decay_factor = math.exp(-decay_rate * interval_secs)  # decay per sample step

    event_idx = 0  # pointer into sorted contributions
    num_events = len(contributions)
    current_score = 0.0

    # Pre-seed: compute initial score at start_epoch from any events before the window
    # (there shouldn't be any since query is WHERE timestamp >= start_iso, but be safe)

    for i in range(num_points):
        t_sample = start_epoch + i * interval_secs
        sample_dt = datetime.fromtimestamp(t_sample, tz=UTC)
        labels.append(sample_dt.strftime("%Y-%m-%dT%H:%M:%SZ"))

        if i > 0:
            # Decay existing score by one interval step
            current_score *= decay_factor

        # Add contributions from events that occurred in this interval
        # (between previous sample and current sample)
        while event_idx < num_events and contributions[event_idx][0] <= t_sample:
            t_event, weight = contributions[event_idx]
            # Decay this event's weight from its actual time to the sample point
            dt = t_sample - t_event
            current_score += weight * math.exp(-decay_rate * dt)
            event_idx += 1

        scores.append(round(current_score, 2))

    _t2 = _time.time()
    current_score = scores[-1] if scores else 0.0
    logger.info(
        "score-history: computation took %.3fs (%d events, %d points, score=%.2f) for host=%s",
        _t2 - _t1,
        num_events,
        num_points,
        current_score,
        hostname,
    )

    return jsonify(
        {
            "labels": labels,
            "scores": scores,
            "threshold": threshold,
            "hostname": hostname,
            "hours": hours,
        }
    )


@host_threats_bp.route("/admin/host-threats/summary")
@login_required
def host_summary_cards():
    """Return per-host summary card data for all active hosts.

    Query params:
        hostname: Filter to a single host (optional)
        page: Page number, 1-based (default 1)
        per_page: Cards per page (default 30)
        half_life: Decay half-life in seconds (default 1800)
        threshold: Alert threshold (default 100)

    Returns JSON with pagination metadata:
    {
        "cards": [
            {
                "hostname": "web-01",
                "effective_score": 85.2,
                "event_count": 42,
                "top_rules": ["sigma_reverse_shell", "sigma_priv_esc", "sigma_cred_dump"],
                "last_detection": "2024-01-15T10:30:00Z",
                "gauge_color": "yellow",
                "gauge_percent": 85.2,
                "mode": "alerting",
                "learning_remaining_hours": null
            },
            ...
        ],
        "total": 75,
        "page": 1,
        "total_pages": 3,
        "has_next": true,
        "has_prev": false
    }
    """
    hostname_filter = request.args.get("hostname", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 30, type=int)
    half_life = request.args.get("half_life", _DEFAULT_HALF_LIFE, type=float)
    threshold = request.args.get("threshold", _DEFAULT_THRESHOLD, type=float)

    # Clamp page to at least 1
    if page < 1:
        page = 1

    # Past 24 hours
    now = datetime.now(UTC)
    since = now - timedelta(hours=24)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    now_epoch = now.timestamp()

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Build query based on hostname filter
        if hostname_filter:
            rows = db.execute(
                "SELECT hostname, timestamp, event_type, rule_name, node_id "
                "FROM host_events WHERE timestamp >= ? AND hostname = ? "
                "ORDER BY hostname, timestamp ASC",
                (since_iso, hostname_filter),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT hostname, timestamp, event_type, rule_name, node_id "
                "FROM host_events WHERE timestamp >= ? "
                "ORDER BY hostname, timestamp ASC",
                (since_iso,),
            ).fetchall()

        # Group events by hostname
        hosts: dict[str, list[dict]] = {}
        host_node_ids: dict[str, str] = {}  # hostname -> most recent node_id
        for row in rows:
            hostname = row["hostname"]
            if hostname not in hosts:
                hosts[hostname] = []
            hosts[hostname].append(
                {
                    "timestamp": row["timestamp"],
                    "event_type": row["event_type"],
                    "rule_name": row["rule_name"],
                }
            )
            # Track the node_id for each hostname (last one seen)
            host_node_ids[hostname] = row["node_id"]

        # Include all known hosts with auditd enabled, even those with no events
        if hostname_filter:
            all_nodes = db.execute(
                "SELECT node_id, display_name, last_host_info FROM nodes WHERE display_name = ?",
                (hostname_filter,),
            ).fetchall()
        else:
            all_nodes = db.execute(
                "SELECT node_id, display_name, last_host_info FROM nodes",
            ).fetchall()
        for node in all_nodes:
            hn = node["display_name"]
            if not hn or hn in hosts:
                continue
            try:
                hi = (
                    json.loads(node["last_host_info"])
                    if isinstance(node["last_host_info"], str)
                    else node["last_host_info"]
                )
                if not isinstance(hi, dict):
                    continue
                has_auditd = "auditd" in hi and isinstance(hi["auditd"], dict)
                parsers = hi.get("active_parsers", [])
                if not has_auditd and "auditd" not in (
                    parsers if isinstance(parsers, list) else []
                ):
                    continue
            except (json.JSONDecodeError, TypeError, AttributeError):
                continue
            hosts[hn] = []
            host_node_ids[hn] = node["node_id"]

        # Fetch mode and liveness status from nodes.last_host_info for all relevant node_ids
        node_mode_info: dict[
            str, dict
        ] = {}  # node_id -> {mode, learning_started_at, learning_duration_hours, last_seen_at, agent_version}
        unique_node_ids = list(set(host_node_ids.values()))
        if unique_node_ids:
            placeholders = ",".join(["?"] * len(unique_node_ids))
            node_rows = db.execute(
                f"SELECT node_id, last_host_info, last_seen_at, agent_version FROM nodes WHERE node_id IN ({placeholders})",
                unique_node_ids,
            ).fetchall()
            for nrow in node_rows:
                try:
                    raw_hi = nrow["last_host_info"]
                    hi = json.loads(raw_hi) if isinstance(raw_hi, str) else raw_hi
                    if isinstance(hi, dict):
                        auditd = hi.get("auditd", {})
                        if isinstance(auditd, dict):
                            node_mode_info[nrow["node_id"]] = {
                                "mode": auditd.get("mode", "unknown"),
                                "learning_started_at": auditd.get("learning_started_at"),
                                "learning_duration_hours": auditd.get("learning_duration_hours"),
                                "last_seen_at": nrow["last_seen_at"],
                                "agent_version": nrow["agent_version"],
                            }
                except (json.JSONDecodeError, TypeError):
                    pass

            # Fetch agent versions from config_agent_status (fallback for monitor agent)
            cas_rows = db.execute(
                f"SELECT node_id, agent_version FROM config_agent_status WHERE node_id IN ({placeholders})",
                unique_node_ids,
            ).fetchall()
            for crow in cas_rows:
                nid = crow["node_id"]
                if nid in node_mode_info:
                    # Only use config_agent_version if nodes.agent_version is not set
                    if not node_mode_info[nid].get("agent_version") and crow["agent_version"]:
                        node_mode_info[nid]["agent_version"] = crow["agent_version"]
                else:
                    node_mode_info[nid] = {"agent_version": crow["agent_version"]}

        # Apply suppression per host and compute summaries
        summaries = []
        for hostname, events in hosts.items():
            node_id = host_node_ids.get(hostname, "")

            # Resolve effective profile for suppression
            profile = resolve_effective_profile(db, node_id) if node_id else None

            # Apply suppression filtering
            filtered_events = _apply_suppression(events, profile)

            # Compute effective score from filtered events
            score = 0.0
            for ev in filtered_events:
                t_event = _iso_to_epoch(ev["timestamp"])
                weight = _get_severity_weight(ev["event_type"])
                dt = now_epoch - t_event
                if dt >= 0:
                    score += weight * (2.0 ** (-(dt) / half_life))

            # Count events
            event_count = len(filtered_events)

            # Top 3 rules by frequency (include grouped_count when grouping is active)
            rule_counts: dict[str, int] = {}
            rule_grouped_counts: dict[str, int] = {}
            for ev in filtered_events:
                rn = ev["rule_name"]
                rule_counts[rn] = rule_counts.get(rn, 0) + 1
                gc = ev.get("grouped_count")
                if gc is not None and gc > 1:
                    rule_grouped_counts[rn] = rule_grouped_counts.get(rn, 0) + gc
            top_rule_names = sorted(rule_counts.keys(), key=lambda r: rule_counts[r], reverse=True)[
                :3
            ]
            top_rules = []
            for rn in top_rule_names:
                rule_obj: dict = {"name": rn, "count": rule_counts[rn]}
                if rn in rule_grouped_counts:
                    rule_obj["grouped_count"] = rule_grouped_counts[rn]
                top_rules.append(rule_obj)

            # Last detection timestamp
            last_detection = filtered_events[-1]["timestamp"] if filtered_events else ""

            # Gauge coloring based on score relative to threshold
            score_percent = (score / threshold) * 100 if threshold > 0 else 0
            if score_percent >= 100:
                gauge_color = "red"
            elif score_percent >= 50:
                gauge_color = "yellow"
            else:
                gauge_color = "green"

            # Mode status from nodes
            mode_data = node_mode_info.get(node_id, {})
            mode = mode_data.get("mode", "unknown") if mode_data else "unknown"
            last_seen_at = mode_data.get("last_seen_at") if mode_data else None
            agent_version = mode_data.get("agent_version") if mode_data else None
            learning_remaining_hours = None

            if mode == "learning":
                learning_started_at = mode_data.get("learning_started_at")
                learning_duration_hours = mode_data.get("learning_duration_hours")
                if learning_started_at is not None and learning_duration_hours is not None:
                    try:
                        started_epoch = float(learning_started_at)
                        duration_h = int(learning_duration_hours)
                        hours_elapsed = (now_epoch - started_epoch) / 3600
                        learning_remaining_hours = max(0, round(duration_h - hours_elapsed))
                    except (ValueError, TypeError):
                        learning_remaining_hours = None

            summaries.append(
                {
                    "hostname": hostname,
                    "effective_score": round(score, 2),
                    "event_count": event_count,
                    "top_rules": top_rules,
                    "last_detection": last_detection,
                    "gauge_color": gauge_color,
                    "gauge_percent": round(min(score_percent, 200), 1),  # cap at 200% for display
                    "mode": mode,
                    "learning_remaining_hours": learning_remaining_hours,
                    "last_seen_at": last_seen_at,
                    "agent_version": agent_version,
                }
            )
    finally:
        db.close()

    # Sort by effective_score descending (most threatened hosts first)
    summaries.sort(key=lambda s: s["effective_score"], reverse=True)

    # Pagination: paginate when >50 hosts have detections
    total = len(summaries)
    if total > 50:
        total_pages = max(1, math.ceil(total / per_page))
        # Clamp page to valid range
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * per_page
        paginated_cards = summaries[offset : offset + per_page]
    else:
        # No pagination needed for <=50 hosts
        total_pages = 1
        page = 1
        paginated_cards = summaries

    return jsonify(
        {
            "cards": paginated_cards,
            "total": total,
            "page": page,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        }
    )


@host_threats_bp.route("/admin/host-threats/suppress", methods=["POST"])
@login_required
def suppress_rules():
    """Apply bulk rule suppression to a host's config profile.

    Accepts a JSON body with `hostname` and `rules`, resolves the host's
    effective config profile, and performs a set-union merge of the requested
    rules into the profile's `suppress_rules` list.

    Request body:
        {
            "hostname": "web-01",
            "rules": ["sigma_cron_execution", "sigma_apt_update"]
        }

    Returns JSON:
        {"success": true, "total_suppressed": N}

    Error responses:
        400 {"error": "invalid_request"} — missing/malformed body
        404 {"error": "host_not_found"} — no node record for hostname
        400 {"error": "no_profile_assigned"} — host has no config profile
        500 {"error": "malformed_profile_settings"} — profile settings JSON corrupted

    Requirements: 5.3, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7
    """
    # Parse and validate JSON body
    body = request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_request"}), 400

    hostname = body.get("hostname")
    rules = body.get("rules")

    # Validate hostname: string, 1–255 chars
    if not isinstance(hostname, str) or len(hostname) < 1 or len(hostname) > 255:
        return jsonify({"error": "invalid_request"}), 400

    # Validate rules: array of strings, 1–500 items, each non-empty
    if not isinstance(rules, list):
        return jsonify({"error": "invalid_request"}), 400
    if len(rules) < 1 or len(rules) > 500:
        return jsonify({"error": "invalid_request"}), 400
    if not all(isinstance(r, str) and len(r) > 0 for r in rules):
        return jsonify({"error": "invalid_request"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Resolve node_id from hostname via host_events
        node_row = db.execute(
            "SELECT node_id FROM host_events WHERE hostname = ? LIMIT 1",
            (hostname,),
        ).fetchone()

        if node_row is None:
            return jsonify({"error": "host_not_found"}), 404

        node_id = node_row["node_id"]

        # Resolve effective profile for this node
        profile = resolve_effective_profile(db, node_id)
        if profile is None:
            return jsonify({"error": "no_profile_assigned"}), 400

        # Parse profile settings JSON
        settings_raw = profile.get("settings", "{}")
        try:
            if isinstance(settings_raw, str):
                settings = json.loads(settings_raw)
            elif isinstance(settings_raw, dict):
                settings = settings_raw
            else:
                settings = {}
            if not isinstance(settings, dict):
                raise ValueError("settings is not a dict")
        except (json.JSONDecodeError, TypeError, ValueError):
            logger.error(
                "Malformed profile settings for profile id=%s: %r",
                profile.get("id"),
                settings_raw,
            )
            return jsonify({"error": "malformed_profile_settings"}), 500

        # Perform set-union merge of requested rules into existing suppress_rules
        existing_suppress = settings.get("suppress_rules", [])
        if not isinstance(existing_suppress, list):
            existing_suppress = []

        new_suppress_rules = list(set(existing_suppress) | set(rules))
        settings["suppress_rules"] = new_suppress_rules

        # Write updated settings back to config_profiles table
        updated_settings_json = json.dumps(settings)
        db.execute(
            "UPDATE config_profiles SET settings = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') "
            "WHERE id = ?",
            (updated_settings_json, profile["id"]),
        )
        db.commit()

        return jsonify(
            {
                "success": True,
                "total_suppressed": len(new_suppress_rules),
            }
        )
    finally:
        db.close()


@host_threats_bp.route("/admin/host-threats/disable-rules", methods=["POST"])
@login_required
def disable_host_threat_rules():
    """Apply bulk rule disable to a host's config profile.

    Accepts a JSON body with `hostname` and `rules`, resolves the host's
    effective config profile, and performs a set-union merge of the requested
    rules into the profile's `disabled_host_threat_rules` list. Disabled rules
    are NOT distributed to the agent, so they never fire or ship data.

    Request body:
        {
            "hostname": "web-01",
            "rules": ["sigma_cron_execution", "sigma_apt_update"]
        }

    Returns JSON:
        {"success": true, "total_disabled": N}
    """
    body = request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_request"}), 400

    hostname = body.get("hostname")
    rules = body.get("rules")

    if not isinstance(hostname, str) or len(hostname) < 1 or len(hostname) > 255:
        return jsonify({"error": "invalid_request"}), 400

    if not isinstance(rules, list):
        return jsonify({"error": "invalid_request"}), 400
    if len(rules) < 1 or len(rules) > 500:
        return jsonify({"error": "invalid_request"}), 400
    if not all(isinstance(r, str) and len(r) > 0 for r in rules):
        return jsonify({"error": "invalid_request"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        node_row = db.execute(
            "SELECT node_id FROM host_events WHERE hostname = ? LIMIT 1",
            (hostname,),
        ).fetchone()

        if node_row is None:
            return jsonify({"error": "host_not_found"}), 404

        node_id = node_row["node_id"]
        profile = resolve_effective_profile(db, node_id)
        if profile is None:
            return jsonify({"error": "no_profile_assigned"}), 400

        settings_raw = profile.get("settings", "{}")
        try:
            if isinstance(settings_raw, str):
                settings = json.loads(settings_raw)
            elif isinstance(settings_raw, dict):
                settings = settings_raw
            else:
                settings = {}
            if not isinstance(settings, dict):
                raise ValueError("settings is not a dict")
        except (json.JSONDecodeError, TypeError, ValueError):
            logger.error(
                "Malformed profile settings for profile id=%s: %r",
                profile.get("id"),
                settings_raw,
            )
            return jsonify({"error": "malformed_profile_settings"}), 500

        existing_disabled = settings.get("disabled_host_threat_rules", [])
        if not isinstance(existing_disabled, list):
            existing_disabled = []

        new_disabled_rules = list(set(existing_disabled) | set(rules))
        settings["disabled_host_threat_rules"] = new_disabled_rules

        updated_settings_json = json.dumps(settings)
        db.execute(
            "UPDATE config_profiles SET settings = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') "
            "WHERE id = ?",
            (updated_settings_json, profile["id"]),
        )
        db.commit()

        return jsonify(
            {
                "success": True,
                "total_disabled": len(new_disabled_rules),
            }
        )
    finally:
        db.close()


@host_threats_bp.route("/admin/host-threats/unsuppress", methods=["POST"])
@login_required
def unsuppress_rules():
    """Remove rules from a host's suppress_rules list.

    Accepts a JSON body with `hostname` and `rules`, resolves the host's
    effective config profile, and performs a set-difference removal of the
    requested rules from the profile's `suppress_rules` list.

    Request body:
        {"hostname": "web-01", "rules": ["sigma_cron_execution"]}

    Returns JSON:
        {"success": true, "total_unsuppressed": N}
    """
    body = request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_request"}), 400

    hostname = body.get("hostname")
    rules = body.get("rules")

    if not isinstance(hostname, str) or len(hostname) < 1 or len(hostname) > 255:
        return jsonify({"error": "invalid_request"}), 400

    if not isinstance(rules, list):
        return jsonify({"error": "invalid_request"}), 400
    if len(rules) < 1 or len(rules) > 500:
        return jsonify({"error": "invalid_request"}), 400
    if not all(isinstance(r, str) and len(r) > 0 for r in rules):
        return jsonify({"error": "invalid_request"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        node_row = db.execute(
            "SELECT node_id FROM host_events WHERE hostname = ? LIMIT 1",
            (hostname,),
        ).fetchone()
        if node_row is None:
            return jsonify({"error": "host_not_found"}), 404

        node_id = node_row["node_id"]
        profile = resolve_effective_profile(db, node_id)
        if profile is None:
            return jsonify({"error": "no_profile_assigned"}), 400

        settings_raw = profile.get("settings", "{}")
        try:
            if isinstance(settings_raw, str):
                settings = json.loads(settings_raw)
            elif isinstance(settings_raw, dict):
                settings = settings_raw
            else:
                settings = {}
            if not isinstance(settings, dict):
                raise ValueError("settings is not a dict")
        except (json.JSONDecodeError, TypeError, ValueError):
            logger.error(
                "Malformed profile settings for profile id=%s: %r",
                profile.get("id"),
                settings_raw,
            )
            return jsonify({"error": "malformed_profile_settings"}), 500

        rules_set = set(rules)
        existing_suppress = settings.get("suppress_rules", [])
        if not isinstance(existing_suppress, list):
            existing_suppress = []

        new_suppress_rules = [r for r in existing_suppress if r not in rules_set]
        removed_count = len(existing_suppress) - len(new_suppress_rules)
        settings["suppress_rules"] = new_suppress_rules

        updated_settings_json = json.dumps(settings)
        db.execute(
            "UPDATE config_profiles SET settings = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') "
            "WHERE id = ?",
            (updated_settings_json, profile["id"]),
        )
        db.commit()

        return jsonify(
            {
                "success": True,
                "total_unsuppressed": removed_count,
            }
        )
    finally:
        db.close()


@host_threats_bp.route("/admin/host-threats/enable-rules", methods=["POST"])
@login_required
def enable_host_threat_rules():
    """Remove rules from a host's disabled_host_threat_rules list.

    Accepts a JSON body with `hostname` and `rules`, resolves the host's
    effective config profile, and performs a set-difference removal of the
    requested rules from the profile's `disabled_host_threat_rules` list.
    Re-enabled rules will be distributed to the agent on next poll.

    Request body:
        {"hostname": "web-01", "rules": ["sigma_cron_execution"]}

    Returns JSON:
        {"success": true, "total_enabled": N}
    """
    body = request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_request"}), 400

    hostname = body.get("hostname")
    rules = body.get("rules")

    if not isinstance(hostname, str) or len(hostname) < 1 or len(hostname) > 255:
        return jsonify({"error": "invalid_request"}), 400

    if not isinstance(rules, list):
        return jsonify({"error": "invalid_request"}), 400
    if len(rules) < 1 or len(rules) > 500:
        return jsonify({"error": "invalid_request"}), 400
    if not all(isinstance(r, str) and len(r) > 0 for r in rules):
        return jsonify({"error": "invalid_request"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        node_row = db.execute(
            "SELECT node_id FROM host_events WHERE hostname = ? LIMIT 1",
            (hostname,),
        ).fetchone()
        if node_row is None:
            return jsonify({"error": "host_not_found"}), 404

        node_id = node_row["node_id"]
        profile = resolve_effective_profile(db, node_id)
        if profile is None:
            return jsonify({"error": "no_profile_assigned"}), 400

        settings_raw = profile.get("settings", "{}")
        try:
            if isinstance(settings_raw, str):
                settings = json.loads(settings_raw)
            elif isinstance(settings_raw, dict):
                settings = settings_raw
            else:
                settings = {}
            if not isinstance(settings, dict):
                raise ValueError("settings is not a dict")
        except (json.JSONDecodeError, TypeError, ValueError):
            logger.error(
                "Malformed profile settings for profile id=%s: %r",
                profile.get("id"),
                settings_raw,
            )
            return jsonify({"error": "malformed_profile_settings"}), 500

        rules_set = set(rules)
        existing_disabled = settings.get("disabled_host_threat_rules", [])
        if not isinstance(existing_disabled, list):
            existing_disabled = []

        new_disabled_rules = [r for r in existing_disabled if r not in rules_set]
        removed_count = len(existing_disabled) - len(new_disabled_rules)
        settings["disabled_host_threat_rules"] = new_disabled_rules

        updated_settings_json = json.dumps(settings)
        db.execute(
            "UPDATE config_profiles SET settings = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') "
            "WHERE id = ?",
            (updated_settings_json, profile["id"]),
        )
        db.commit()

        return jsonify(
            {
                "success": True,
                "total_enabled": removed_count,
            }
        )
    finally:
        db.close()


@host_threats_bp.route("/admin/host-threats/set-mode", methods=["POST"])
@login_required
def set_host_threat_mode():
    """Set the auditd mode for a host via a queued server command.

    Accepts a JSON body with `hostname` and `mode`, resolves the host's
    node_id, and creates a pending `set_auditd_mode` command for the
    agent to pick up on its next heartbeat poll.

    Request body:
        {"hostname": "web-01", "mode": "alerting"}

    Valid modes: learning, detecting, alerting

    Returns JSON:
        {"success": true, "mode": "alerting"}
    """
    body = request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_request"}), 400

    hostname = body.get("hostname")
    mode = body.get("mode")

    if not isinstance(hostname, str) or len(hostname) < 1 or len(hostname) > 255:
        return jsonify({"error": "invalid_request"}), 400

    if mode not in ("learning", "detecting", "alerting"):
        return jsonify(
            {
                "error": "invalid_request",
                "message": "mode must be 'learning', 'detecting', or 'alerting'",
            }
        ), 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        node_row = db.execute(
            "SELECT node_id FROM host_events WHERE hostname = ? LIMIT 1",
            (hostname,),
        ).fetchone()
        if node_row is None:
            return jsonify({"error": "host_not_found"}), 404

        node_id = node_row["node_id"]

        # Queue the command for the agent to pick up
        create_command(db, node_id, "set_auditd_mode", {"mode": mode})

        logger.info("Queued set_auditd_mode=%s command for node %s (%s)", mode, node_id, hostname)
        return jsonify({"success": True, "mode": mode})
    finally:
        db.close()


# ── Alert Notification Dispatch ───────────────────────────────────────────


def _dispatch_host_alert_notification(
    db,
    hostname: str,
    node_id: str,
    score: float,
    profile_id: int,
    top_rules: list[dict] | None = None,
    event_count: int = 0,
    last_detection: str = "",
    gauge_color: str = "green",
    mode: str = "unknown",
    max_severity_weight: int = 0,
) -> None:
    """Check threshold and cooldown, then send a notification if warranted.

    Reads the alert config from the host_threat_alert_config table for the
    given profile_id, checks whether a notification was already sent within
    the cooldown period, and if not, dispatches the notification.

    Episode-based alerting with escalation: while a host's score stays above
    threshold we normally stay quiet (one notification per episode). If the
    host's maximum detection severity tier increases beyond the tier recorded
    for the current episode (e.g. a critical detection arrives during a
    medium episode), a new escalation notification is dispatched and the
    episode's recorded tier is raised.

    Args:
        db: Open DB connection.
        hostname: The host that crossed the threshold.
        node_id: The host's node_id.
        score: The current effective score.
        profile_id: The config profile id.
        top_rules: Top detection rules contributing to the score.
        event_count: Number of filtered events in the scoring window.
        last_detection: ISO timestamp of the most recent detection.
        gauge_color: Color indicator (green/yellow/red).
        mode: The host's auditd mode.
        max_severity_weight: Highest severity weight among the host's
            filtered events in the scoring window (50 critical .. 1
            informational). 0 when unknown.
    """
    # Look up alert config from the dedicated table
    alert_row = db.execute(
        "SELECT threshold, cooldown_seconds, notify_channel "
        "FROM host_threat_alert_config WHERE profile_id = ?",
        (profile_id,),
    ).fetchone()

    if not alert_row:
        return

    threshold = alert_row["threshold"]
    if not isinstance(threshold, (int, float)) or threshold <= 0:
        threshold = _DEFAULT_THRESHOLD

    now_iso = datetime.now(UTC).isoformat()

    # ── Episode-based alerting ────────────────────────────────────────
    # A host threat "episode" starts when the score crosses the threshold
    # and ends when it drops back below. We only notify once per episode:
    # - score >= threshold AND no unresolved notification → NEW episode → send
    # - score >= threshold AND unresolved notification exists → already
    #   alerted for this episode → stay quiet (no 60s re-alert spam)
    # - score < threshold AND unresolved notification exists → resolve the
    #   episode so the next crossing triggers a fresh alert
    active_row = db.execute(
        "SELECT id, created_at, severity_tier FROM host_threat_notifications "
        "WHERE hostname = ? AND resolved_at IS NULL "
        "ORDER BY created_at DESC LIMIT 1",
        (hostname,),
    ).fetchone()

    if score < threshold:
        if active_row:
            db.execute(
                "UPDATE host_threat_notifications SET resolved_at = ? WHERE id = ?",
                (now_iso, active_row["id"]),
            )
            db.commit()
            logger.info(
                "Host threat episode resolved for %s (score=%.1f < threshold=%.1f)",
                hostname,
                score,
                threshold,
            )
        return

    is_escalation = False
    if active_row:
        prev_tier = 0.0
        if "severity_tier" in active_row.keys():
            try:
                prev_tier = float(active_row["severity_tier"] or 0)
            except (ValueError, TypeError):
                prev_tier = 0.0

        if max_severity_weight > prev_tier and prev_tier > 0:
            # Severity tier increased while the episode is active — alert again
            # and supersede the current episode notification so the higher tier
            # becomes the new baseline.
            is_escalation = True
            db.execute(
                "UPDATE host_threat_notifications SET resolved_at = ? WHERE id = ?",
                (now_iso, active_row["id"]),
            )
            db.commit()
            logger.info(
                "Host threat episode escalated for %s (severity tier %s -> %s, score=%.1f)",
                hostname,
                prev_tier,
                max_severity_weight,
                score,
            )
        elif max_severity_weight > prev_tier:
            # Legacy episode with no recorded tier: record the current tier as
            # the baseline without re-alerting (avoids a burst on upgrade).
            db.execute(
                "UPDATE host_threat_notifications SET severity_tier = ? WHERE id = ?",
                (max_severity_weight, active_row["id"]),
            )
            db.commit()
            logger.info(
                "Host threat episode baseline tier set for %s (tier=%s)",
                hostname,
                max_severity_weight,
            )
            return
        else:
            # Still firing for the current episode — already alerted, do not spam.
            logger.debug(
                "Host threat already active for %s (score=%.1f); skipping duplicate notification",
                hostname,
                score,
            )
            return

    cooldown_seconds = alert_row["cooldown_seconds"]
    if not isinstance(cooldown_seconds, (int, float)) or cooldown_seconds < 60:
        cooldown_seconds = 900

    # Parse notify_channel
    raw_channel = alert_row["notify_channel"]
    notify = {}
    if isinstance(raw_channel, str):
        try:
            notify = json.loads(raw_channel)
        except (json.JSONDecodeError, TypeError):
            notify = {}
    elif isinstance(raw_channel, dict):
        notify = raw_channel

    if not notify or not isinstance(notify, dict):
        return

    channel_type = notify.get("type")
    if channel_type not in ("webhook", "discord", "slack", "email"):
        return

    channel_target = notify.get("url") or notify.get("to") or ""

    # For discord/slack, look up the notification_channels table if no URL in profile
    if channel_type in ("discord", "slack") and not channel_target:
        try:
            from app.models import get_notification_channels

            channels = get_notification_channels(db, enabled=True)
            for ch in channels:
                if ch.get("type") == channel_type:
                    cfg = ch.get("config", {})
                    if isinstance(cfg, str):
                        try:
                            cfg = json.loads(cfg)
                        except (json.JSONDecodeError, TypeError):
                            cfg = {}
                    if isinstance(cfg, dict):
                        channel_target = cfg.get("url") or cfg.get("webhook_url") or ""
                        if channel_target:
                            logger.info(
                                "Resolved %s channel '%s' from notification_channels for %s",
                                channel_type,
                                ch.get("name", "?"),
                                hostname,
                            )
                            break
        except Exception as exc:
            logger.warning(
                "Failed to resolve %s channel from notification_channels: %s", channel_type, exc
            )

    if not channel_target:
        logger.warning(
            "No %s channel configured for %s and no enabled %s channel found in notification_channels",
            channel_type,
            hostname,
            channel_type,
        )
        return

    # Check cooldown period

    # Look up the most recent notification for this host
    last_row = db.execute(
        "SELECT created_at, status FROM host_threat_notifications "
        "WHERE hostname = ? AND status = 'sent' "
        "ORDER BY created_at DESC LIMIT 1",
        (hostname,),
    ).fetchone()

    if last_row and not is_escalation:
        try:
            last_created = last_row["created_at"]
            if isinstance(last_created, str):
                last_dt = datetime.fromisoformat(last_created.replace("Z", "+00:00"))
            else:
                # MySQL returns a datetime object. If naive, treat it as UTC
                # so the comparison with the aware `now` below is valid.
                last_dt = last_created
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=UTC)
            now_dt = datetime.now(UTC)
            seconds_since = (now_dt - last_dt).total_seconds()
            if seconds_since < cooldown_seconds:
                logger.debug(
                    "Skipping notification for %s: last sent %.0fs ago (cooldown=%ds)",
                    hostname,
                    seconds_since,
                    cooldown_seconds,
                )
                return
        except (ValueError, TypeError):
            pass

    severity = "critical" if score >= threshold * 2 else _get_severity_name(max_severity_weight)
    rule_lines = ""
    if top_rules:
        for r in top_rules:
            cnt = r.get("count", 0)
            gc = r.get("grouped_count")
            if gc:
                rule_lines += f"  • {r['name']} ({cnt} events, ~{gc} grouped)\n"
            else:
                rule_lines += f"  • {r['name']} ({cnt} events)\n"

    # Build common payload
    payload = {
        "event": "host_threat_alert",
        "hostname": hostname,
        "score": round(score, 2),
        "threshold": threshold,
        "severity": severity,
        "severity_tier": max_severity_weight,
        "escalation": is_escalation,
        "timestamp": now_iso,
        "dashboard_url": f"/admin/host-threats?hostname={hostname}",
        "event_count": event_count,
        "last_detection": last_detection,
        "gauge_color": gauge_color,
        "mode": mode,
    }
    if top_rules:
        payload["top_rules"] = [{"name": r["name"], "count": r.get("count", 0)} for r in top_rules]

    status = "sent"
    error_message = None

    try:
        if channel_type == "webhook":
            resp = requests.post(
                channel_target,
                json=payload,
                timeout=15,
                headers={"User-Agent": "Vespid-Server/1.0"},
            )
            resp.raise_for_status()
            logger.info(
                "Host threat alert dispatched via webhook for %s (score=%.1f, threshold=%.1f)",
                hostname,
                score,
                threshold,
            )

        elif channel_type == "discord":
            embed = {
                "title": (
                    f"Host Threat Escalation — {hostname}"
                    if is_escalation
                    else f"Host Threat Alert — {hostname}"
                ),
                "color": 0xEF4444 if severity == "critical" else 0xF59E0B,
                "fields": [
                    {"name": "Hostname", "value": hostname, "inline": True},
                    {
                        "name": "Score",
                        "value": f"{score:.1f} (threshold: {threshold})",
                        "inline": True,
                    },
                    {"name": "Severity", "value": severity.upper(), "inline": True},
                    {"name": "Mode", "value": mode, "inline": True},
                    {"name": "Events (24h)", "value": str(event_count), "inline": True},
                    {"name": "Last Detection", "value": last_detection or "—", "inline": True},
                ],
                "footer": {"text": f"Vespid Server • {now_iso[:19]}"},
            }
            if top_rules:
                rule_text = "\n".join(f"• {r['name']} ({r.get('count', 0)})" for r in top_rules[:5])
                embed["fields"].append(
                    {
                        "name": "Top Detections",
                        "value": rule_text or "None",
                        "inline": False,
                    }
                )
            discord_payload = {"embeds": [embed]}
            resp = requests.post(
                channel_target,
                json=discord_payload,
                timeout=15,
                headers={"User-Agent": "Vespid-Server/1.0"},
            )
            resp.raise_for_status()
            logger.info(
                "Host threat alert dispatched via Discord for %s (score=%.1f)",
                hostname,
                score,
            )

        elif channel_type == "slack":
            color_hex = "#EF4444" if severity == "critical" else "#F59E0B"
            alert_label = "Host Threat Escalation" if is_escalation else "Host Threat Alert"
            blocks = [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"⚠️ {alert_label} — {hostname}"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Hostname:*\n{hostname}"},
                        {
                            "type": "mrkdwn",
                            "text": f"*Score:*\n{score:.1f} (threshold: {threshold})",
                        },
                        {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                        {"type": "mrkdwn", "text": f"*Mode:*\n{mode}"},
                    ],
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Events (24h):*\n{event_count}"},
                        {"type": "mrkdwn", "text": f"*Last Detection:*\n{last_detection or '—'}"},
                    ],
                },
            ]
            if top_rules:
                rule_lines_slack = "\n".join(
                    f"• `{r['name']}` — {r.get('count', 0)} events" for r in top_rules[:5]
                )
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Top Detections:*\n{rule_lines_slack}",
                        },
                    }
                )
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"<{payload['dashboard_url']}|Open Dashboard>",
                    },
                }
            )
            slack_payload = {
                "text": f"{alert_label} — {hostname} (score: {score:.1f})",
                "attachments": [{"color": color_hex, "blocks": blocks}],
            }
            resp = requests.post(
                channel_target,
                json=slack_payload,
                timeout=15,
                headers={"User-Agent": "Vespid-Server/1.0"},
            )
            resp.raise_for_status()
            logger.info(
                "Host threat alert dispatched via Slack for %s (score=%.1f)",
                hostname,
                score,
            )

        elif channel_type == "email":
            to_addr = notify.get("to", "")
            if to_addr:
                subject_label = "Host Threat Escalation" if is_escalation else "Host Threat Alert"
                body = (
                    f"{subject_label}\n\n"
                    f"Host: {hostname}\n"
                    f"Score: {score:.1f} (threshold: {threshold})\n"
                    f"Severity: {'CRITICAL' if severity == 'critical' else 'WARNING'}\n"
                    f"Mode: {mode}\n"
                    f"Time: {now_iso}\n"
                    f"Events (24h): {event_count}\n"
                    f"Last Detection: {last_detection or '—'}\n"
                )
                if rule_lines:
                    body += f"Top Detections:\n{rule_lines}\n"
                body += f"Dashboard: {payload['dashboard_url']}\n"
                msg = MIMEText(body)
                msg["Subject"] = f"[Vespid] {subject_label} — {hostname}"
                msg["From"] = current_app.config.get("MAIL_FROM", "vespid@localhost")
                msg["To"] = to_addr

                mail_host = current_app.config.get("MAIL_HOST", "localhost")
                mail_port = current_app.config.get("MAIL_PORT", 25)
                mail_user = current_app.config.get("MAIL_USER", "")
                mail_pass = current_app.config.get("MAIL_PASS", "")

                smtp = smtplib.SMTP(mail_host, mail_port, timeout=15)
                if mail_user and mail_pass:
                    smtp.starttls()
                    smtp.login(mail_user, mail_pass)
                smtp.send_message(msg)
                smtp.quit()

                logger.info(
                    "Host threat alert emailed to %s for %s (score=%.1f)",
                    to_addr,
                    hostname,
                    score,
                )
    except requests.RequestException as exc:
        status = "failed"
        error_message = str(exc)
        logger.warning(
            "Webhook notification failed for %s: %s",
            hostname,
            exc,
        )
    except smtplib.SMTPException as exc:
        status = "failed"
        error_message = str(exc)
        logger.warning(
            "Email notification failed for %s: %s",
            hostname,
            exc,
        )
    except Exception as exc:
        status = "failed"
        error_message = str(exc)
        logger.warning(
            "Notification dispatch failed for %s: %s",
            hostname,
            exc,
        )

    # Record the notification attempt
    try:
        db.execute(
            "INSERT INTO host_threat_notifications "
            "(hostname, profile_id, channel_type, channel_target, score, threshold, "
            "severity_tier, status, error_message) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                hostname,
                profile_id,
                channel_type,
                channel_target,
                score,
                threshold,
                max_severity_weight,
                status,
                error_message,
            ),
        )
        db.commit()
    except Exception as exc:
        logger.error("Failed to record notification in DB: %s", exc)


@host_threats_bp.route("/admin/host-threats/acknowledge", methods=["POST"])
@login_required
def acknowledge_host_alert():
    """Acknowledge a host threat alert notification.

    Request body:
        {"hostname": "web-01", "acknowledged_by": "admin"}

    Marks the most recent 'sent' notification for this host as acknowledged.
    """
    body = request.get_json(silent=True)
    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_request"}), 400

    hostname = body.get("hostname")
    acknowledged_by = body.get("acknowledged_by", "")

    if not isinstance(hostname, str) or len(hostname) < 1:
        return jsonify({"error": "invalid_request"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        db.execute(
            "UPDATE host_threat_notifications "
            "SET acknowledged_at = ?, acknowledged_by = ? "
            "WHERE hostname = ? AND status = 'sent' AND acknowledged_at IS NULL",
            (now_iso, acknowledged_by, hostname),
        )
        db.commit()
        logger.info(
            "Acknowledged host threat alert for %s by %s",
            hostname,
            acknowledged_by or "unknown",
        )
        return jsonify({"success": True, "hostname": hostname})
    finally:
        db.close()


@host_threats_bp.route("/admin/host-threats/notifications")
@login_required
def host_threat_notifications():
    """Return host threat notification history.

    Query params:
        hostname: Filter to a single host (optional)
        limit: Max results (default 50)

    Returns JSON array of notification records.
    """
    hostname = request.args.get("hostname", "").strip()
    limit = request.args.get("limit", 50, type=int)
    limit = max(1, min(limit, 200))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        if hostname:
            rows = db.execute(
                "SELECT id, hostname, channel_type, channel_target, score, threshold, status, "
                "acknowledged_at, acknowledged_by, error_message, created_at "
                "FROM host_threat_notifications WHERE hostname = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (hostname, limit),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT id, hostname, channel_type, channel_target, score, threshold, status, "
                "acknowledged_at, acknowledged_by, error_message, created_at "
                "FROM host_threat_notifications ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

        results = []
        for row in rows:
            results.append(
                {
                    "id": row["id"],
                    "hostname": row["hostname"],
                    "channel_type": row["channel_type"],
                    "channel_target": row["channel_target"],
                    "score": row["score"],
                    "threshold": row["threshold"],
                    "status": row["status"],
                    "acknowledged_at": row["acknowledged_at"],
                    "acknowledged_by": row["acknowledged_by"],
                    "error_message": row["error_message"],
                    "created_at": row["created_at"],
                }
            )
        return jsonify({"notifications": results, "total": len(results)})
    finally:
        db.close()


@host_threats_bp.route("/admin/host-threats/alert-config")
@login_required
def host_threat_alert_config():
    """Return the host threat alert notification configurations from all profiles.

    Returns JSON:
    {
        "profiles": [
            {
                "profile_id": 1,
                "profile_name": "Default",
                "threshold": 100,
                "cooldown_seconds": 900,
                "notify_channel": {"type": "webhook", "url": "https://..."}
            },
            ...
        ]
    }
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        profiles = db.execute(
            "SELECT p.id, p.name, "
            "COALESCE(c.threshold, ?) AS threshold, "
            "COALESCE(c.cooldown_seconds, 900) AS cooldown_seconds, "
            "c.notify_channel, "
            "c.id AS config_id "
            "FROM config_profiles p "
            "LEFT JOIN host_threat_alert_config c ON c.profile_id = p.id "
            "WHERE p.is_active = 1",
            (_DEFAULT_THRESHOLD,),
        ).fetchall()

        result = []
        for row in profiles:
            channel_raw = row["notify_channel"]
            channel = {}
            if channel_raw:
                if isinstance(channel_raw, str):
                    try:
                        channel = json.loads(channel_raw)
                    except (json.JSONDecodeError, TypeError):
                        channel = {}
                elif isinstance(channel_raw, dict):
                    channel = channel_raw

            result.append(
                {
                    "profile_id": row["id"],
                    "profile_name": row["name"],
                    "threshold": row["threshold"],
                    "cooldown_seconds": row["cooldown_seconds"],
                    "notify_channel": channel,
                    "has_config": row["config_id"] is not None,
                }
            )

        return jsonify({"profiles": result, "total": len(result)})
    finally:
        db.close()


@host_threats_bp.route("/admin/host-threats/alert-config", methods=["POST"])
@login_required
def host_threat_alert_config_save():
    """Create or update a host threat alert config for a profile.

    Expects JSON body:
    {
        "profile_id": 1,
        "threshold": 100,
        "cooldown_seconds": 900,
        "notify_channel": {"type": "webhook", "url": "https://..."}
    }
    """
    data = request.get_json(silent=True) or {}
    profile_id = data.get("profile_id")
    if not profile_id:
        return jsonify({"error": "profile_id is required"}), 400

    threshold = data.get("threshold", _DEFAULT_THRESHOLD)
    cooldown_seconds = data.get("cooldown_seconds", 900)
    notify_channel = data.get("notify_channel", {})

    if not isinstance(threshold, (int, float)) or threshold <= 0:
        threshold = _DEFAULT_THRESHOLD
    if not isinstance(cooldown_seconds, (int, float)) or cooldown_seconds < 60:
        cooldown_seconds = 900

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        existing = db.execute(
            "SELECT id FROM host_threat_alert_config WHERE profile_id = ?",
            (profile_id,),
        ).fetchone()

        now_iso = datetime.now(UTC).isoformat()
        channel_json = json.dumps(notify_channel) if isinstance(notify_channel, dict) else "{}"

        if existing:
            db.execute(
                "UPDATE host_threat_alert_config "
                "SET threshold = ?, cooldown_seconds = ?, notify_channel = ?, updated_at = ? "
                "WHERE profile_id = ?",
                (threshold, cooldown_seconds, channel_json, now_iso, profile_id),
            )
        else:
            db.execute(
                "INSERT INTO host_threat_alert_config "
                "(profile_id, threshold, cooldown_seconds, notify_channel) "
                "VALUES (?, ?, ?, ?)",
                (profile_id, threshold, cooldown_seconds, channel_json),
            )
        db.commit()

        return jsonify({"success": True, "profile_id": profile_id})
    finally:
        db.close()


@host_threats_bp.route("/admin/host-threats/alert-config/<int:profile_id>", methods=["DELETE"])
@login_required
def host_threat_alert_config_delete(profile_id: int):
    """Delete a host threat alert config for a profile."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        db.execute(
            "DELETE FROM host_threat_alert_config WHERE profile_id = ?",
            (profile_id,),
        )
        db.commit()
        return jsonify({"success": True})
    finally:
        db.close()


def compute_host_threat_active(
    db,
    since_iso: str,
    now_epoch: float,
    half_life: float,
    threshold: float,
) -> list[dict]:
    """Compute per-host threat scores for the past 24h.

    Shared by the production view (display) and the background alert scan
    (notification dispatch), so notifications fire on a timer instead of
    only when an admin happens to visit the dashboard.

    Returns:
        List of dicts, each with hostname, node_id, effective_score,
        event_count, top_rules, last_detection, gauge_color, gauge_percent,
        mode, profile_id (may be None if no profile is assigned).
    """
    rows = db.execute(
        "SELECT hostname, timestamp, event_type, rule_name, node_id "
        "FROM host_events WHERE timestamp >= ? "
        "ORDER BY hostname, timestamp ASC",
        (since_iso,),
    ).fetchall()

    hosts: dict[str, list[dict]] = {}
    host_node_ids: dict[str, str] = {}
    for row in rows:
        hostname = row["hostname"]
        if hostname not in hosts:
            hosts[hostname] = []
        hosts[hostname].append(
            {
                "timestamp": row["timestamp"],
                "event_type": row["event_type"],
                "rule_name": row["rule_name"],
            }
        )
        host_node_ids[hostname] = row["node_id"]

        # Fetch mode and liveness status from nodes
        node_mode_info: dict[str, dict] = {}
        unique_node_ids = list(set(host_node_ids.values()))
        if unique_node_ids:
            placeholders = ",".join(["?"] * len(unique_node_ids))
            node_rows = db.execute(
                f"SELECT node_id, last_host_info, last_seen_at, agent_version FROM nodes WHERE node_id IN ({placeholders})",
                unique_node_ids,
            ).fetchall()
            for nrow in node_rows:
                try:
                    raw_hi = nrow["last_host_info"]
                    hi = json.loads(raw_hi) if isinstance(raw_hi, str) else raw_hi
                    if isinstance(hi, dict):
                        auditd = hi.get("auditd", {})
                        if isinstance(auditd, dict):
                            node_mode_info[nrow["node_id"]] = {
                                "mode": auditd.get("mode", "unknown"),
                                "last_seen_at": nrow["last_seen_at"],
                                "agent_version": nrow["agent_version"],
                            }
                except (json.JSONDecodeError, TypeError):
                    pass

            # Fetch agent versions from config_agent_status (fallback for monitor agent)
            cas_rows = db.execute(
                f"SELECT node_id, agent_version FROM config_agent_status WHERE node_id IN ({placeholders})",
                unique_node_ids,
            ).fetchall()
            for crow in cas_rows:
                nid = crow["node_id"]
                if nid in node_mode_info:
                    # Only use config_agent_version if nodes.agent_version is not set
                    if not node_mode_info[nid].get("agent_version") and crow["agent_version"]:
                        node_mode_info[nid]["agent_version"] = crow["agent_version"]
                else:
                    node_mode_info[nid] = {"agent_version": crow["agent_version"]}

    # Compute summaries (same as summary endpoint)
    active = []
    for hostname, events in hosts.items():
        node_id = host_node_ids.get(hostname, "")
        profile = resolve_effective_profile(db, node_id) if node_id else None
        filtered_events = _apply_suppression(events, profile)

        score = 0.0
        max_severity_weight = 0
        for ev in filtered_events:
            t_event = _iso_to_epoch(ev["timestamp"])
            weight = _get_severity_weight(ev["event_type"])
            if weight > max_severity_weight:
                max_severity_weight = weight
            dt = now_epoch - t_event
            if dt >= 0:
                score += weight * (2.0 ** (-(dt) / half_life))

        # Skip hosts with no active threat score
        if score <= 0:
            continue

        event_count = len(filtered_events)

        rule_counts: dict[str, int] = {}
        rule_grouped_counts: dict[str, int] = {}
        for ev in filtered_events:
            rn = ev["rule_name"]
            rule_counts[rn] = rule_counts.get(rn, 0) + 1
            gc = ev.get("grouped_count")
            if gc is not None and gc > 1:
                rule_grouped_counts[rn] = rule_grouped_counts.get(rn, 0) + gc
        top_rule_names = sorted(rule_counts.keys(), key=lambda r: rule_counts[r], reverse=True)[:3]
        top_rules = []
        for rn in top_rule_names:
            rule_obj: dict = {"name": rn, "count": rule_counts[rn]}
            if rn in rule_grouped_counts:
                rule_obj["grouped_count"] = rule_grouped_counts[rn]
            top_rules.append(rule_obj)

        last_detection = filtered_events[-1]["timestamp"] if filtered_events else ""

        score_percent = (score / threshold) * 100 if threshold > 0 else 0
        if score_percent >= 100:
            gauge_color = "red"
        elif score_percent >= 50:
            gauge_color = "yellow"
        else:
            gauge_color = "green"

        mode_data = node_mode_info.get(node_id, {})
        mode = mode_data.get("mode", "unknown") if mode_data else "unknown"
        last_seen_at = mode_data.get("last_seen_at") if mode_data else None
        agent_version = mode_data.get("agent_version") if mode_data else None

        active.append(
            {
                "hostname": hostname,
                "node_id": node_id,
                "profile_id": profile["id"] if profile else None,
                "effective_score": round(score, 2),
                "max_severity_weight": max_severity_weight,
                "event_count": event_count,
                "top_rules": top_rules,
                "last_detection": last_detection,
                "gauge_color": gauge_color,
                "gauge_percent": round(min(score_percent, 200), 1),
                "mode": mode,
                "last_seen_at": last_seen_at,
                "agent_version": agent_version,
            }
        )

    active.sort(key=lambda h: h["effective_score"], reverse=True)
    return active


def evaluate_host_threat_alerts(db) -> None:
    """Background scan: compute host threat scores and dispatch notifications.

    Runs on the alert-eval timer (independent of page views) so operators
    are notified without having to open the dashboard.
    """
    now = datetime.now(UTC)
    since = now - timedelta(hours=24)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    now_epoch = now.timestamp()

    try:
        active = compute_host_threat_active(
            db, since_iso, now_epoch, _DEFAULT_HALF_LIFE, _DEFAULT_THRESHOLD
        )
    except Exception:
        logger.exception("Host threat alert scan failed")
        return

    # Continuous score feed: log each active host's current score every
    # scan cycle (independent of browser activity) so operators have a
    # persistent record of threat scores over time.
    for host in active:
        logger.info(
            "host-threat-scan: host=%s score=%.2f events=%d last_detection=%s",
            host.get("hostname"),
            host.get("effective_score", 0.0),
            host.get("event_count", 0),
            host.get("last_detection", ""),
        )

    for host in active:
        node_id = host.get("node_id")
        profile_id = host.get("profile_id")
        if not node_id or not profile_id:
            continue
        try:
            _dispatch_host_alert_notification(
                db,
                host["hostname"],
                node_id,
                host["effective_score"],
                profile_id,
                top_rules=host.get("top_rules"),
                event_count=host.get("event_count"),
                last_detection=host.get("last_detection"),
                gauge_color=host.get("gauge_color"),
                mode=host.get("mode"),
                max_severity_weight=host.get("max_severity_weight", 0),
            )
        except Exception:
            logger.exception("Host threat alert dispatch failed for %s", host.get("hostname"))


@host_threats_bp.route("/admin/host-threats/production")
@login_required
def host_production_view():
    """Return hosts with active threat scores for the production alert view.

    Display-only — notifications are dispatched by the background alert
    scan (evaluate_host_threat_alerts), not as a side-effect of this GET.

    Returns JSON:
    {
        "hosts": [
            {
                "hostname": "web-01",
                "effective_score": 285.3,
                "event_count": 42,
                "top_rules": [...],
                "last_detection": "...",
                "gauge_color": "red",
                "gauge_percent": 285.3,
                "mode": "alerting"
            },
            ...
        ],
        "total_active": 5
    }
    """
    half_life = request.args.get("half_life", _DEFAULT_HALF_LIFE, type=float)
    threshold = request.args.get("threshold", _DEFAULT_THRESHOLD, type=float)

    now = datetime.now(UTC)
    since = now - timedelta(hours=24)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    now_epoch = now.timestamp()

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        active = compute_host_threat_active(db, since_iso, now_epoch, half_life, threshold)
    finally:
        db.close()

    # Strip internal dispatch fields from the display payload
    public_hosts = []
    for host in active:
        public_hosts.append(
            {
                "hostname": host["hostname"],
                "effective_score": host["effective_score"],
                "event_count": host["event_count"],
                "top_rules": host["top_rules"],
                "last_detection": host["last_detection"],
                "gauge_color": host["gauge_color"],
                "gauge_percent": host["gauge_percent"],
                "mode": host["mode"],
                "last_seen_at": host.get("last_seen_at"),
                "agent_version": host.get("agent_version"),
            }
        )

    return jsonify(
        {
            "hosts": public_hosts,
            "total_active": len(public_hosts),
        }
    )


@host_threats_bp.route("/admin/host-threats/events")
@login_required
def host_threats_events():
    """Return paginated host events as JSON for the Timeline Table panel.

    Query params:
        hostname: Filter by hostname (optional)
        page: Page number, 1-based (default 1)
        per_page: Events per page (default 200)

    Returns JSON:
    {
        "events": [
            {
                "id": 1,
                "hostname": "web-01",
                "timestamp": "2024-01-15T10:30:00Z",
                "event_type": "high",
                "rule_name": "sigma_reverse_shell",
                "pid": 1234,
                "ppid": 1000,
                "exe": "/bin/bash",
                "command_line": "bash -i >& /dev/tcp/...",
                "uid": 1000,
                "auid": 1000
            },
            ...
        ],
        "total": 12500,
        "page": 1,
        "total_pages": 63,
        "has_next": true,
        "has_prev": false
    }

    Requirements: 5.1, 5.2, 10.3
    """
    hostname_filter = request.args.get("hostname", "").strip()
    pid_filter = request.args.get("pid", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 200, type=int)

    # Clamp page to at least 1
    if page < 1:
        page = 1

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Resolve suppression rules for this host so the COUNT and query
        # both exclude suppressed/disabled rules at the DB level.
        suppress_rule_names: list[str] = []
        node_id_for_profile: str | None = None

        if hostname_filter:
            node_row = db.execute(
                "SELECT node_id FROM host_events WHERE hostname = ? LIMIT 1",
                (hostname_filter,),
            ).fetchone()
            if node_row:
                node_id_for_profile = node_row["node_id"]
                profile = resolve_effective_profile(db, node_id_for_profile)
                if profile:
                    try:
                        settings_raw = profile.get("settings", "{}")
                        if isinstance(settings_raw, str):
                            psettings = json.loads(settings_raw)
                        elif isinstance(settings_raw, dict):
                            psettings = settings_raw
                        else:
                            psettings = {}
                        if isinstance(psettings, dict):
                            sr = psettings.get("suppress_rules", [])
                            if isinstance(sr, list):
                                suppress_rule_names.extend(r for r in sr if isinstance(r, str))
                            dr = psettings.get("disabled_host_threat_rules", [])
                            if isinstance(dr, list):
                                suppress_rule_names.extend(r for r in dr if isinstance(r, str))
                    except (json.JSONDecodeError, TypeError):
                        pass

        # Build the SQL exclusion clause for suppressed rules
        exclude_clause = ""
        exclude_params: list[str] = []
        if suppress_rule_names:
            # Deduplicate
            unique_suppressed = list(set(suppress_rule_names))
            placeholders = ",".join(["?"] * len(unique_suppressed))
            exclude_clause = f" AND rule_name NOT IN ({placeholders})"
            exclude_params = unique_suppressed

        # Use indexed queries on hostname and timestamp columns
        if hostname_filter and pid_filter:
            count_row = db.execute(
                f"SELECT COUNT(*) FROM host_events WHERE hostname = ? AND pid = ?{exclude_clause}",
                [hostname_filter, pid_filter] + exclude_params,
            ).fetchone()
            total = count_row[0]

            rows = db.execute(
                f"SELECT id, hostname, timestamp, event_type, rule_name, "
                "pid, ppid, exe, command_line, uid, auid, node_id "
                f"FROM host_events WHERE hostname = ? AND pid = ?{exclude_clause} "
                "ORDER BY timestamp DESC "
                "LIMIT ? OFFSET ?",
                [hostname_filter, pid_filter] + exclude_params + [per_page, (page - 1) * per_page],
            ).fetchall()
        elif hostname_filter:
            count_row = db.execute(
                f"SELECT COUNT(*) FROM host_events WHERE hostname = ?{exclude_clause}",
                [hostname_filter] + exclude_params,
            ).fetchone()
            total = count_row[0]

            rows = db.execute(
                f"SELECT id, hostname, timestamp, event_type, rule_name, "
                "pid, ppid, exe, command_line, uid, auid, node_id "
                f"FROM host_events WHERE hostname = ?{exclude_clause} "
                "ORDER BY timestamp DESC "
                "LIMIT ? OFFSET ?",
                [hostname_filter] + exclude_params + [per_page, (page - 1) * per_page],
            ).fetchall()
        else:
            count_row = db.execute(
                "SELECT COUNT(*) FROM host_events",
            ).fetchone()
            total = count_row[0]

            rows = db.execute(
                "SELECT id, hostname, timestamp, event_type, rule_name, "
                "pid, ppid, exe, command_line, uid, auid, node_id "
                "FROM host_events "
                "ORDER BY timestamp DESC "
                "LIMIT ? OFFSET ?",
                (per_page, (page - 1) * per_page),
            ).fetchall()

        events = [dict(r) for r in rows]

        # Apply suppression filtering per hostname
        # Group events by hostname to resolve profiles
        if events:
            # Collect unique node_ids from events
            node_ids_in_page = list({e.get("node_id", "") for e in events if e.get("node_id")})

            # Resolve effective profiles for each node_id
            profiles_by_node: dict[str, dict | None] = {}
            for nid in node_ids_in_page:
                profiles_by_node[nid] = resolve_effective_profile(db, nid)

            # Group events by node_id for suppression
            events_by_node: dict[str, list[dict]] = {}
            events_no_node: list[dict] = []
            for e in events:
                nid = e.get("node_id", "")
                if nid:
                    if nid not in events_by_node:
                        events_by_node[nid] = []
                    events_by_node[nid].append(e)
                else:
                    events_no_node.append(e)

            # Apply suppression per node group
            filtered_events = []
            for nid, node_events in events_by_node.items():
                profile = profiles_by_node.get(nid)
                filtered = _apply_suppression(node_events, profile)
                filtered_events.extend(filtered)

            # Events without node_id pass through unsuppressed
            filtered_events.extend(events_no_node)

            # Re-sort by timestamp descending after suppression
            filtered_events.sort(
                key=lambda e: _iso_to_epoch(e.get("timestamp", "")),
                reverse=True,
            )

            events = filtered_events
    finally:
        db.close()

    # Compute pagination metadata
    total_pages = max(1, math.ceil(total / per_page))

    # Clamp page to valid range
    if page > total_pages:
        page = total_pages

    # Build clean event dicts for response (include pid, ppid for process tree linking)
    response_events = []
    for e in events:
        event_dict = {
            "id": e.get("id"),
            "hostname": e.get("hostname"),
            "timestamp": e.get("timestamp"),
            "event_type": e.get("event_type"),
            "rule_name": e.get("rule_name"),
            "pid": e.get("pid"),
            "ppid": e.get("ppid"),
            "exe": e.get("exe"),
            "command_line": e.get("command_line"),
            "uid": e.get("uid"),
            "auid": e.get("auid"),
        }
        # Include grouped_count if present from suppression grouping
        if "grouped_count" in e:
            event_dict["grouped_count"] = e["grouped_count"]
        response_events.append(event_dict)

    return jsonify(
        {
            "events": response_events,
            "total": total,
            "page": page,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        }
    )


# ── Noise Analysis Endpoint ──────────────────────────────────────────────────


@host_threats_bp.route("/admin/host-threats/noise-analysis")
@login_required
def noise_analysis():
    """Return learning-period detection rules ranked by fire count.

    Queries all events during a host's learning period, aggregates by
    rule_name, and returns results sorted by fire_count descending.

    Query params:
        hostname: Target host identifier (required, 1–255 chars)

    Returns JSON:
    {
        "hostname": "web-01",
        "learning_start": "2024-01-14T10:00:00Z",
        "learning_end": "2024-01-15T10:00:00Z",
        "rules": [
            {
                "rule_name": "sigma_cron_execution",
                "fire_count": 847,
                "severity": "low",
                "sample_command": "/usr/sbin/cron -f"
            }
        ]
    }

    Error responses:
        400: {"error": "missing_hostname"} — hostname absent or empty
        404: {"error": "host_not_found"} — no node record for hostname
        404: {"error": "no_learning_data"} — node lacks learning period data

    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 8.1, 8.2, 8.4, 8.5, 8.6, 8.7
    """
    hostname = request.args.get("hostname", "").strip()

    # Validate hostname: non-empty, ≤255 chars
    if not hostname or len(hostname) > 255:
        return jsonify({"error": "missing_hostname"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Look up node_id for this hostname from host_events
        node_row = db.execute(
            "SELECT node_id FROM host_events WHERE hostname = ? LIMIT 1",
            (hostname,),
        ).fetchone()

        if node_row is None:
            return jsonify({"error": "host_not_found"}), 404

        node_id = node_row["node_id"]

        # Load node record and parse last_host_info
        node_info_row = db.execute(
            "SELECT last_host_info FROM nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()

        if node_info_row is None:
            return jsonify({"error": "host_not_found"}), 404

        # Parse last_host_info JSON
        raw_hi = node_info_row["last_host_info"]
        try:
            hi = json.loads(raw_hi) if isinstance(raw_hi, str) else raw_hi
        except (json.JSONDecodeError, TypeError):
            hi = None

        if not isinstance(hi, dict):
            return jsonify({"error": "no_learning_data"}), 404

        auditd = hi.get("auditd")
        if not isinstance(auditd, dict):
            return jsonify({"error": "no_learning_data"}), 404

        learning_started_at = auditd.get("learning_started_at")
        learning_duration_hours = auditd.get("learning_duration_hours")

        if learning_started_at is None or learning_duration_hours is None:
            return jsonify({"error": "no_learning_data"}), 404

        # Compute learning window
        try:
            started_epoch = float(learning_started_at)
            duration_hours = float(learning_duration_hours)
        except (ValueError, TypeError):
            return jsonify({"error": "no_learning_data"}), 404

        end_epoch = started_epoch + (duration_hours * 3600)
        now_epoch = datetime.now(UTC).timestamp()

        # If current time is before the computed end, use current time as end
        if now_epoch < end_epoch:
            end_epoch = now_epoch

        # Convert epochs to ISO strings for the query
        learning_start_dt = datetime.fromtimestamp(started_epoch, tz=UTC)
        learning_end_dt = datetime.fromtimestamp(end_epoch, tz=UTC)
        learning_start_iso = learning_start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        learning_end_iso = learning_end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Query host_events using the composite index idx_host_events_hostname_timestamp
        rows = db.execute(
            "SELECT rule_name, event_type, command_line, timestamp "
            "FROM host_events "
            "WHERE hostname = ? AND timestamp >= ? AND timestamp <= ? "
            "ORDER BY timestamp DESC",
            (hostname, learning_start_iso, learning_end_iso),
        ).fetchall()

        # Resolve current profile state for suppress/disable badges
        profile = resolve_effective_profile(db, node_id)
        current_suppressed: set[str] = set()
        current_disabled: set[str] = set()
        if profile:
            settings_raw = profile.get("settings", "{}")
            try:
                settings = (
                    json.loads(settings_raw) if isinstance(settings_raw, str) else settings_raw
                )
                sr = settings.get("suppress_rules", [])
                if isinstance(sr, list):
                    current_suppressed = {r for r in sr if isinstance(r, str)}
                dr = settings.get("disabled_host_threat_rules", [])
                if isinstance(dr, list):
                    current_disabled = {r for r in dr if isinstance(r, str)}
            except (json.JSONDecodeError, TypeError):
                pass

        # Aggregate by rule_name
        rule_agg: dict[str, dict] = {}
        for row in rows:
            rule_name = row["rule_name"] or ""
            if rule_name not in rule_agg:
                # Normalize severity from event_type
                raw_event_type = (row["event_type"] or "").lower()
                severity = "low"  # default
                for sev in ("critical", "high", "medium", "low"):
                    if sev in raw_event_type:
                        severity = sev
                        break

                rule_agg[rule_name] = {
                    "rule_name": rule_name,
                    "fire_count": 0,
                    "severity": severity,
                    "sample_command": row["command_line"] or "",
                    "_latest_ts": row["timestamp"] or "",
                    "is_default_noise": is_default_noise(rule_name),
                    "is_suppressed": rule_name in current_suppressed,
                    "is_disabled": rule_name in current_disabled,
                }
            rule_agg[rule_name]["fire_count"] += 1
            # Pick the most recent command_line (rows are ordered DESC by timestamp,
            # so first occurrence per rule is the most recent)

        # Build rules list
        rules = list(rule_agg.values())

        # Remove internal tracking field
        for r in rules:
            r.pop("_latest_ts", None)

        # Sort: descending by fire_count, ascending by rule_name for ties
        rules.sort(key=lambda r: (-r["fire_count"], r["rule_name"]))

        return jsonify(
            {
                "hostname": hostname,
                "learning_start": learning_start_iso,
                "learning_end": learning_end_iso,
                "rules": rules,
            }
        )
    finally:
        db.close()

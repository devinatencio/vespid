"""API blueprint — event ingestion, SSE streaming, export, and command stub.

Endpoints:
    POST /api/v1/events                          — Ingest event batch (Bearer token auth)
    GET  /api/v1/events/stream                   — SSE stream of new events (session auth)
    GET  /api/v1/events/export                   — Export filtered events (analyst+ role)
    GET  /api/v1/nodes/<node_id>/commands        — Stub, returns 501
    POST /api/v1/unlock-webhook/<ip>            — Unblock IP via pre-shared secret (no auth)

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 5.1, 5.2, 5.3, 5.4,
              7.3, 11.4, 12.1, 12.2, 12.3, 16.1
"""

import hmac
import ipaddress
import json
import logging
from datetime import UTC, datetime, timedelta

from flask import Response, current_app, jsonify, request
from flask_login import current_user
from flask_openapi3 import APIBlueprint
from flask_openapi3.models import Tag

from app.decorators import require_role
from app.export import export_csv, export_json
from app.geo import lookup as geo_lookup
from app.host_ingest import process_host_threat_events
from app.intel_models import get_attack_vectors, process_fleet_block_event, process_unblock_event
from app.intel_service import process_block_event, process_sighting, query_ip_record
from app.inventory import ensure_asset, update_asset_seen
from app.models import (
    acknowledge_command,
    get_db,
    get_event_context,
    get_pending_commands,
    get_request_db,
    insert_counter_snapshots,
    insert_event_context,
    insert_events,
    record_audit,
    search_events,
    touch_node,
    update_api_key_last_used,
    update_last_seen,
    upsert_node,
)
from app.openapi_models import (
    EventBatchErrorResponse,
    EventBatchResponse,
    VerifyAPIKeyResponse,
)
from app.rate_limit import _key_func_body_node, limiter
from app.routes.auth import authenticate_bearer_token
from app.validators import validate_batch

logger = logging.getLogger(__name__)

_nodes_tag = [Tag(name="Nodes", description="Node management and heartbeats")]
_events_tag = [Tag(name="Events", description="Security event ingestion and streaming")]

api_bp = APIBlueprint("api", __name__, url_prefix="/api/v1")


def _parse_asn_number(asn_value) -> int | None:
    """Parse an ASN value into an integer.

    Handles formats like "AS12345", "12345", or integer 12345.
    Returns None if the value cannot be parsed or is out of valid range.
    """
    if asn_value is None:
        return None
    if isinstance(asn_value, int):
        return asn_value if 1 <= asn_value <= 4294967295 else None
    if isinstance(asn_value, str):
        # Strip "AS" or "as" prefix
        cleaned = asn_value.strip()
        if cleaned.upper().startswith("AS"):
            cleaned = cleaned[2:]
        try:
            num = int(cleaned)
            return num if 1 <= num <= 4294967295 else None
        except (ValueError, TypeError):
            return None
    return None


MAX_FUTURE_SKEW = timedelta(minutes=5)


def validate_event_timestamp(event_timestamp_str: str) -> tuple[bool, str]:
    """Validate agent timestamp is not too far in the future.

    Returns (is_valid, error_message).
    Past timestamps are always accepted.

    Requirements: 21.2, 21.3
    """
    try:
        event_ts = datetime.fromisoformat(event_timestamp_str.rstrip("Z")).replace(tzinfo=UTC)
    except (ValueError, TypeError) as exc:
        return False, f"Invalid timestamp format '{event_timestamp_str}': {exc}"

    server_now = datetime.now(UTC)

    if event_ts > server_now + MAX_FUTURE_SKEW:
        return (
            False,
            f"Event timestamp {event_timestamp_str} is more than 5 minutes in the future",
        )

    return True, ""


_authenticate_api_key = authenticate_bearer_token


@api_bp.get(
    "/verify",
    summary="Verify API key",
    description="Confirm a Bearer token is a valid, active API key. Used by agents during enrollment validation.",
    tags=_nodes_tag,
    security=[{"BearerAuth": []}],
    responses={
        200: VerifyAPIKeyResponse,
        401: {"description": "Missing, invalid, or revoked API key"},
    },
)
@limiter.exempt
def verify_api_key():
    """Verify that a Bearer token is a valid, active API key.

    Used by agents during enrollment validation to confirm a newly-
    issued key is recognized by the server before entering full
    operational mode.

    Returns:
        200 with ``{"ok": true, "node_id": "..."}`` on valid key.
        401 on missing, invalid, or revoked key.

    Requirements: 22.1, 22.2
    """
    api_key, error_response = _authenticate_api_key()
    if error_response is not None:
        return error_response

    node_id = api_key.get("node_id_restriction", "")
    return jsonify({"ok": True, "node_id": node_id}), 200


@api_bp.post(
    "/events",
    summary="Ingest event batch",
    description="Submit a batch of 1-100 security events. Authenticates via Bearer token, validates the batch, "
    "persists valid events, updates API key last_used_at, upserts node registry entries, "
    "publishes events to SSE, and returns a summary response.\n\n"
    "Rate limited per API key (default: 60 requests/minute).",
    tags=_events_tag,
    security=[{"BearerAuth": []}],
    responses={
        200: EventBatchResponse,
        400: {"description": "Invalid JSON or empty batch"},
        401: {"description": "Missing or invalid API key"},
        403: {"description": "All events rejected due to node_id mismatch"},
        422: EventBatchErrorResponse,
    },
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_EVENTS_INGEST", "60 per minute"))
def ingest_events():
    """Ingest a batch of SecurityEvents.

    Authenticates via Bearer token, validates the batch, persists valid
    events, updates API key last_used_at, upserts node registry entries,
    publishes events to SSE, and returns a summary response.

    Rate limited per API key (default: 60 requests/minute).

    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 7.3, 11.4
    """
    # Authenticate
    api_key, error_response = _authenticate_api_key()
    if error_response is not None:
        return error_response

    # Parse JSON body
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    if body is None:
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    if not isinstance(body, dict) or "events" not in body:
        return jsonify(
            {"error": "missing_events", "message": "Request body must contain an 'events' array"}
        ), 400

    events_list = body["events"]
    if not isinstance(events_list, list):
        return jsonify(
            {"error": "missing_events", "message": "Request body must contain an 'events' array"}
        ), 400

    if len(events_list) == 0:
        return jsonify({"error": "empty_batch", "message": "Events array must not be empty"}), 400

    # Separate host_threat events from regular events before validation.
    # host_threat events have a different schema (no source_ip, event_id, etc.)
    # and are stored in the host_events table rather than the events table.
    host_threat_events: list[tuple[int, dict]] = []  # (original_index, event)
    regular_events: list[dict] = []
    for idx, ev in enumerate(events_list):
        if not isinstance(ev, dict):
            regular_events.append(ev)
            continue
        # Check event_kind at top level or in metadata
        event_kind = ev.get("event_kind", "")
        if not event_kind:
            meta = ev.get("metadata")
            if isinstance(meta, dict):
                event_kind = meta.get("event_kind", "")
        if event_kind == "host_threat":
            host_threat_events.append((idx, ev))
        else:
            regular_events.append(ev)

    # Process host_threat events separately
    host_accepted = 0
    host_rejected: list[dict] = []
    if host_threat_events:
        node_id_restriction = api_key.get("node_id_restriction")
        host_db = get_request_db()
        host_accepted, host_rejected = process_host_threat_events(
            host_db, host_threat_events, node_id_restriction
        )

    # If the entire batch was host_threat events, return early
    if not regular_events:
        rejected_list = [{"index": r["index"], "errors": r["errors"]} for r in host_rejected]
        return jsonify(
            {
                "accepted": host_accepted,
                "rejected": rejected_list,
                "total": len(events_list),
            }
        ), 200

    # Validate the regular (non-host_threat) batch
    validation = validate_batch(regular_events)

    # Enforce node_id restriction if the API key has one
    node_id_restriction = api_key.get("node_id_restriction")
    if node_id_restriction:
        # Move events with non-matching node_ids from valid to rejected
        still_valid = []
        for ev in validation.valid:
            if ev.get("node_id") != node_id_restriction:
                # Find the original index of this event in the batch
                original_index = _find_event_index(events_list, ev)
                validation.errors.append(
                    {
                        "index": original_index,
                        "event_id": ev.get("event_id"),
                        "errors": [
                            f"node_id mismatch: key is restricted to '{node_id_restriction}'"
                        ],
                    }
                )
            else:
                still_valid.append(ev)
        validation.valid = still_valid

        # If ALL events were rejected due to node_id mismatch, return 403
        if len(validation.valid) == 0 and all(
            any("node_id mismatch" in e for e in err.get("errors", [])) for err in validation.errors
        ):
            return jsonify(
                {
                    "error": "node_id_mismatch",
                    "message": f"All events rejected: API key is restricted to node '{node_id_restriction}'",
                }
            ), 403

    # If all regular events failed validation (no valid events), check if
    # host_threat events were processed successfully. If so, return combined result.
    if len(validation.valid) == 0:
        if host_accepted > 0:
            # Some host_threat events were accepted even though all regular
            # events failed. Return a 200 with the combined totals.
            rejected_list = [
                {"index": err["index"], "event_id": err.get("event_id"), "errors": err["errors"]}
                for err in validation.errors
            ]
            for r in host_rejected:
                rejected_list.append({"index": r["index"], "errors": r["errors"]})
            return jsonify(
                {
                    "accepted": host_accepted,
                    "rejected": rejected_list,
                    "total": len(events_list),
                }
            ), 200
        # All events failed
        rejected_list = [
            {"index": err["index"], "event_id": err.get("event_id"), "errors": err["errors"]}
            for err in validation.errors
        ]
        for r in host_rejected:
            rejected_list.append({"index": r["index"], "errors": r["errors"]})
        return jsonify(
            {
                "error": "all_events_invalid",
                "message": "All events in the batch failed validation",
                "rejected": rejected_list,
            }
        ), 422

    # Enrich events with GeoIP data from source_ip when geo_data is missing
    for ev in validation.valid:
        geo = ev.get("geo_data") or {}
        if not geo.get("country"):
            looked_up = geo_lookup(ev["source_ip"])
            if looked_up.get("country"):
                geo.update({k: v for k, v in looked_up.items() if v is not None})
                ev["geo_data"] = geo

    # Persist valid events
    db = get_request_db()

    # Extract surrounding log context from metadata BEFORE the events
    # table insert so the lean metadata is stored in the events row.
    # The context goes into the separate event_log_context table.
    # Also keep a copy keyed by (source_ip, node_id) for the intel pipeline.
    # The intel pipeline only ingests NFT_ACTION events, which have a
    # different event_id than the BLOCKED events that carry surrounding_logs.
    # Grouping by (ip, node) lets us look up the context regardless.
    log_context_map: dict[tuple[str, str], str] = {}
    pending_context: list[tuple[str, list[dict]]] = []
    for ev in validation.valid:
        meta = ev.get("metadata")
        if isinstance(meta, dict) and "surrounding_logs" in meta:
            ctx = meta.pop("surrounding_logs")
            if ctx:
                key = (ev.get("source_ip", ""), ev.get("node_id", ""))
                log_context_map[key] = json.dumps(ctx, separators=(",", ":"))
                if ev.get("event_type") != "NFT_ACTION":
                    pending_context.append((ev["event_id"], ctx))

    inserted_ids = insert_events(db, validation.valid)

    # Store context in the separate table now that events exist.
    for event_id, ctx in pending_context:
        insert_event_context(db, event_id, ctx)

    # Update API key last_used_at
    update_api_key_last_used(db, api_key["id"])

    # Upsert node registry for each distinct node_id
    seen_nodes = set()
    for ev in validation.valid:
        nid = ev["node_id"]
        if nid not in seen_nodes:
            seen_nodes.add(nid)
        upsert_node(db, nid, ev["timestamp"], ev.get("geo_data", {}))

    # Update agent liveness for each distinct node
    for nid in seen_nodes:
        update_last_seen(db, nid)

    # Publish events to SSE manager as rendered HTML fragments
    _event_row_tpl = current_app.jinja_env.get_template("fragments/event_row.html")
    sse_manager = current_app.sse_manager

    # Check which of these source IPs have active fleet blocks
    _fleet_blocked_ips: set[str] = set()
    _source_ips = list({ev["source_ip"] for ev in validation.valid})
    if _source_ips:
        _db_fleet = get_request_db()
        _placeholders = ",".join("?" * len(_source_ips))
        _rows = _db_fleet.execute(
            f"SELECT DISTINCT source_ip FROM fleet_blocks WHERE source_ip IN ({_placeholders}) AND status = 'active'",
            _source_ips,
        ).fetchall()
        _fleet_blocked_ips = {row[0] for row in _rows}

    for ev in validation.valid:
        if ev.get("event_type") == "NFT_ACTION":
            continue

        sse_ev = dict(ev)
        geo = sse_ev.get("geo_data") or {}
        sse_ev.setdefault("geo_country", geo.get("country"))
        sse_ev.setdefault("geo_asn", geo.get("asn"))
        sse_ev.setdefault("geo_org", geo.get("org"))
        sse_ev["fleet_blocked"] = sse_ev["source_ip"] in _fleet_blocked_ips
        rendered = _event_row_tpl.render(event=sse_ev)
        sse_manager.publish(ev["event_id"], rendered)

    # Forward qualifying block reports to the Propagation Engine
    # An event qualifies as a block report if it has action_taken == "BLOCKED"
    # and includes a detection_rule_name in its metadata.
    # Only forward events that were actually inserted (not duplicates from
    # restart replay or spool drain) to prevent re-creating blocks.
    propagation_engine = getattr(current_app, "propagation_engine", None)
    if propagation_engine is not None:
        for ev in validation.valid:
            if ev.get("event_id") not in inserted_ids:
                continue

            metadata = ev.get("metadata") or {}
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except (json.JSONDecodeError, TypeError):
                    metadata = {}
            action_taken = ev.get("action_taken", "") or metadata.get("action_taken", "")
            detection_rule_name = metadata.get("detection_rule_name", "")

            if (
                action_taken == "BLOCKED"
                and detection_rule_name
                and ev.get("event_type", "") != "NFT_ACTION"
            ):
                block_report = {
                    "source_ip": ev.get("source_ip", ""),
                    "node_id": ev.get("node_id", ""),
                    "event_type": ev.get("event_type", ""),
                    "detection_rule": detection_rule_name,
                    "block_ttl_seconds": metadata.get("block_ttl_seconds", 86400),
                    "event_id": ev.get("event_id", ""),
                }
                try:
                    propagation_engine.process_block_report(block_report)
                except Exception:
                    logger.exception(
                        "Failed to process block report for %s from node %s",
                        block_report.get("source_ip"),
                        block_report.get("node_id"),
                    )

    # Route qualifying events to the Intelligence Database.
    # This enables zero-change agent integration: the existing DataBus
    # telemetry flow automatically feeds the intelligence database.
    # Failures here must NOT break the primary event pipeline.
    #
    # INTEL_INGEST_ACTIONS controls which action_taken values are recorded.
    # Default: "BLOCKED" (only blocked IPs). Set to "BLOCKED,OBSERVED"
    # to also record sightings.  OBSERVED events increment total_times_seen
    # (actual log lines observed).  BLOCKED events increment
    # total_times_blocked.  DETECTED events are intentionally excluded from
    # the intel counter to avoid inflating "Times Seen" with internal
    # detection/correlation events that don't represent new traffic.
    intel_actions_raw = current_app.config.get("INTEL_INGEST_ACTIONS", "BLOCKED")
    intel_actions = {a.strip().upper() for a in intel_actions_raw.split(",") if a.strip()}

    # Single shared connection for the entire intel pipeline — eliminates
    # the per-event open/close cycle that was the biggest DB overhead.
    intel_db = get_request_db()

    for ev in validation.valid:
        try:
            # Skip events that were not actually inserted (spool replays).
            # The main events table deduplicates on event_id, but without
            # this check the intel pipeline would double-count replayed events.
            if ev.get("event_id") not in inserted_ids:
                continue

            metadata = ev.get("metadata") or {}
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except (json.JSONDecodeError, TypeError):
                    metadata = {}

            action_taken = ev.get("action_taken", "") or metadata.get("action_taken", "")
            geo_data = ev.get("geo_data") or {}

            # Fleet block routing: events with event_kind="fleet_block" are
            # routed to process_fleet_block_event() which inserts a visibility
            # row without incrementing counters (Req 15).
            # Exclude UNBLOCKED events — an unblock in fleet context should still
            # go through process_unblock_event() below, not be recorded as a block.
            event_kind = ev.get("event_kind", "") or metadata.get("event_kind", "")
            if event_kind == "fleet_block" and action_taken.upper() != "UNBLOCKED":
                process_fleet_block_event(
                    conn=intel_db,
                    ip_address=ev.get("source_ip", ""),
                    node_id=ev.get("node_id", ""),
                    timestamp=ev.get("timestamp", ""),
                    event_type=ev.get("event_type", "NFT_ACTION"),
                    event_id=ev.get("event_id", ""),
                )
                continue

            # UNBLOCKED events: route to process_unblock_event() for lifecycle
            # tracking (Req 17). Still excluded from counter increments.
            if action_taken.upper() == "UNBLOCKED":
                process_unblock_event(
                    conn=intel_db,
                    ip_address=ev.get("source_ip", ""),
                    timestamp=ev.get("timestamp", ""),
                )
                continue

            if action_taken.upper() not in intel_actions:
                continue

            # Fleet filter: events with metadata.reason starting with "fleet:"
            # are preemptive blocks applied via fleet sync. Route them to
            # process_fleet_block_event() for operational visibility without
            # incrementing counters (Req 7, Req 15).
            # This handles both:
            # - New agents that send event_kind="fleet_block" (caught above)
            # - Old agents that only have metadata.reason="fleet:..." without event_kind
            # Exclude UNBLOCKED events to avoid recording fleet unblocks as blocks.
            reason = metadata.get("reason", "") or ""
            if reason.startswith("fleet:") and action_taken.upper() != "UNBLOCKED":
                process_fleet_block_event(
                    conn=intel_db,
                    ip_address=ev.get("source_ip", ""),
                    node_id=ev.get("node_id", ""),
                    timestamp=ev.get("timestamp", ""),
                    event_type=ev.get("event_type", "NFT_ACTION"),
                    event_id=ev.get("event_id", ""),
                )
                continue

            # Only ingest NFT_ACTION events for BLOCKED actions to avoid
            # double-counting. The agent emits both a detection-level event
            # (e.g. RECON_CORRELATION + BLOCKED) and a confirmation event
            # (NFT_ACTION + BLOCKED) for the same block. The NFT_ACTION is
            # the authoritative "block was applied" signal.
            event_type = ev.get("event_type", "")
            if action_taken.upper() == "BLOCKED" and event_type != "NFT_ACTION":
                continue

            if action_taken == "BLOCKED":
                # Build block event payload for intelligence service
                intel_payload = {
                    "source_ip": ev.get("source_ip", ""),
                    "node_id": ev.get("node_id", ""),
                    "event_type": ev.get("event_type", ""),
                    "timestamp": ev.get("timestamp", ""),
                    "detection_rule": metadata.get("detection_rule_name", ""),
                    "block_ttl_seconds": metadata.get("block_ttl_seconds", 0),
                    "metadata": {
                        "geo_country": geo_data.get("country"),
                        "asn": _parse_asn_number(geo_data.get("asn")),
                        "isp_organization": geo_data.get("org"),
                        "threat_tag": metadata.get("threat_tag"),
                        "request_count": metadata.get("request_count"),
                        "event_id": ev.get("event_id", ""),
                        "log_context": _get_log_context(
                            (ev.get("source_ip", ""), ev.get("node_id", "")),
                            log_context_map,
                        ),
                    },
                }
                # Also pass threat_tag at top level for intel service
                if metadata.get("threat_tag"):
                    intel_payload["threat_tag"] = metadata["threat_tag"]
                process_block_event(intel_db, intel_payload)

            elif action_taken == "OBSERVED":
                # Only OBSERVED events increment total_times_seen so the
                # counter reflects actual requests seen in logs, not
                # internal detection/correlation events.
                intel_payload = {
                    "source_ip": ev.get("source_ip", ""),
                    "node_id": ev.get("node_id", ""),
                    "event_type": ev.get("event_type", ""),
                    "timestamp": ev.get("timestamp", ""),
                    "metadata": {
                        "geo_country": geo_data.get("country"),
                        "asn": _parse_asn_number(geo_data.get("asn")),
                        "isp_organization": geo_data.get("org"),
                        "request_count": metadata.get("request_count"),
                        "event_id": ev.get("event_id", ""),
                    },
                }
                process_sighting(intel_db, intel_payload)

        except Exception:
            logger.warning(
                "Intelligence ingestion failed for event %s from node %s",
                ev.get("event_id", "unknown"),
                ev.get("node_id", "unknown"),
                exc_info=True,
            )

    # Build response
    rejected_list = [
        {"index": err["index"], "event_id": err.get("event_id"), "errors": err["errors"]}
        for err in validation.errors
    ]

    # Merge host_threat rejected events into the response
    for r in host_rejected:
        rejected_list.append({"index": r["index"], "errors": r["errors"]})

    return jsonify(
        {
            "accepted": len(inserted_ids) + host_accepted,
            "rejected": rejected_list,
            "total": len(events_list),
        }
    ), 200


def _find_event_index(events_list, event):
    """Find the original index of an event in the batch by event_id."""
    target_id = event.get("event_id")
    for i, ev in enumerate(events_list):
        if isinstance(ev, dict) and ev.get("event_id") == target_id:
            return i
    return -1


@api_bp.route("/events/stream")
@limiter.exempt
def event_stream():
    """SSE endpoint for streaming new events to dashboard clients.

    Requires session authentication (cookie-based). Supports reconnection
    via the Last-Event-ID header.

    The generator sends a ``:keepalive`` comment every 15 seconds to
    prevent proxies, load balancers, and the gunicorn worker timeout from
    killing idle connections.

    Requirements: 5.1, 5.2, 5.3, 5.4
    """
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized", "message": "Authentication required"}), 401

    last_event_id = request.headers.get("Last-Event-ID")
    sse_manager = current_app.sse_manager

    def generate():
        """Yield SSE messages with periodic keepalive comments.

        Uses a 15-second timeout on queue.get() so we can emit an SSE
        comment (``:``) as a keepalive.  This prevents:
        - Reverse proxies (nginx) from closing idle connections
        - Gunicorn's worker timeout from killing the thread
        - Browsers from assuming the connection is dead
        """
        client_queue = sse_manager.create_client(last_event_id=last_event_id)
        try:
            while True:
                try:
                    message = client_queue.get(timeout=15)
                except Exception:
                    # queue.Empty — no events for 15 s, send keepalive
                    yield ":keepalive\n\n"
                    continue
                if message is None:
                    # Sentinel — server is shutting down
                    return
                yield message
        except GeneratorExit:
            # Client disconnected
            pass
        finally:
            sse_manager.remove_client(client_queue)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "X-SSE-Connection": "events",
        },
    )


@api_bp.route("/events/export")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_EXPORT", "10 per minute"))
@require_role("analyst")
def export_events():
    """Export filtered events as CSV or JSON.

    Requires analyst+ role. Accepts the same filter parameters as event
    search plus a ``format`` query param (csv or json, default json).

    Requirements: 12.1, 12.2, 12.3
    """
    # Collect filter parameters
    filters = {}
    for key in (
        "source_ip",
        "node",
        "node_id",
        "node_name",
        "event_type",
        "start_time",
        "end_time",
        "geo_country",
    ):
        value = request.args.get(key)
        if value:
            filters[key] = value

    export_format = request.args.get("format", "json").lower()

    # Fetch all matching events (no pagination for export)
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        events, _total = search_events(db, filters, page=1, per_page=100000)
    finally:
        db.close()

    if export_format == "csv":
        return export_csv(events)
    else:
        return export_json(events)


@api_bp.route("/events/<event_id>/context")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_DEFAULT", "120 per minute"))
def event_context(event_id):
    """Return the surrounding log context for an event as HTML.

    Used by HTMX lazy-load when the user expands an event detail row.
    Returns an empty ``<details>`` element (no context) for events
    that have no context stored.  Requires session authentication.
    """
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        lines = get_event_context(db, event_id)
    finally:
        db.close()

    if not lines:
        # Fallback: check inline metadata for old events that were
        # ingested before the separate event_log_context table existed.
        db = get_db(db_path)
        try:
            row = db.execute(
                "SELECT metadata FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row:
                meta = row["metadata"]
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except (json.JSONDecodeError, TypeError):
                        meta = {}
                inline = meta.get("surrounding_logs") if isinstance(meta, dict) else None
                if inline:
                    lines = _parse_inline_context(inline)
        finally:
            db.close()

    if not lines:
        return '<p class="log-context-empty">No log context available for this event.</p>'

    # Condensed inline preview: show trigger line + 5 lines above/below
    trigger_idx = next((i for i, ln in enumerate(lines) if ln.get("is_trigger")), len(lines) - 1)
    preview_start = max(0, trigger_idx - 5)
    preview_end = min(len(lines), trigger_idx + 6)
    preview_lines = lines[preview_start:preview_end]

    total_count = sum(ln.get("repeat", 1) for ln in lines)
    parts = ['<details class="log-context" open>']
    parts.append(f"<summary>Surrounding Log Context ({total_count} lines)</summary>")
    parts.append('<pre class="log-context-lines">')
    if preview_start > 0:
        parts.append(f'<span class="log-line-ellipsis">… {preview_start} earlier lines …</span>\n')
    for ln in preview_lines:
        raw = ln["raw"]
        repeat = ln.get("repeat", 1)
        is_trigger = ln.get("is_trigger", False)
        prefix = f"<b>×{repeat}</b>  " if repeat > 1 else ""
        cls = ' class="log-line-trigger"' if is_trigger else ""
        parts.append(f"<span{cls}>{prefix}{_escape_html(raw)}</span>\n")
    if preview_end < len(lines):
        parts.append(
            f'<span class="log-line-ellipsis">… {len(lines) - preview_end} more lines …</span>\n'
        )
    parts.append("</pre>")
    parts.append(
        f'<button class="btn-view-full-context" onclick="openEventModal(\'{event_id}\')">View Full Details →</button>'
    )
    parts.append("</details>")
    return "".join(parts)


def _escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _resolve_node_display_names(node_ids: list) -> list[tuple[str, str]]:
    """Resolve a list of node UUIDs to (node_id, display_name) pairs.

    display_name will be None if no friendly name is set.
    Uses a per-request cache via Flask g.
    """
    if not node_ids:
        return []
    from flask import g

    if not hasattr(g, "_node_display_map"):
        try:
            db = get_db(current_app.config["DATABASE_PATH"])
            rows = db.execute("SELECT node_id, display_name FROM nodes").fetchall()
            g._node_display_map = {
                r["node_id"]: r["display_name"] for r in rows if r["display_name"]
            }
            db.close()
        except Exception:
            g._node_display_map = {}
    return [(nid, g._node_display_map.get(nid)) for nid in node_ids]


def _parse_db_timestamp(value) -> datetime | None:
    """Parse a database timestamp into a timezone-aware UTC datetime.

    Handles MySQL DATETIME (returned as datetime object or space-separated
    string), ISO-8601 strings, and plain ISO without offset.
    """
    if not value:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value
    ts = value.strip()
    if not ts:
        return None
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=UTC)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        pass
    return None


def _get_log_context(key: tuple, batch_map: dict) -> str | None:
    """Return the serialised log context for an (ip, node) key.

    With the agent now including surrounding_logs directly in the
    NFT_ACTION event, the per-batch map is always populated — no
    cross-event or cross-batch linking needed.
    """
    return batch_map.get(key)


def _parse_inline_context(inline: list) -> list[dict]:
    """Convert the old inline ``surrounding_logs`` format to the new table format.

    Handles both the dedup-aware format (with ``repeat``, ``trigger`` keys)
    and the original per-line format.
    """
    lines: list[dict] = []
    for entry in inline:
        if isinstance(entry, dict):
            lines.append(
                {
                    "raw": entry.get("raw", ""),
                    "parser": entry.get("parser"),
                    "is_trigger": bool(entry.get("trigger", False)),
                    "repeat": entry.get("repeat", 1),
                }
            )
        elif isinstance(entry, str):
            lines.append(
                {
                    "raw": entry,
                    "parser": None,
                    "is_trigger": False,
                    "repeat": 1,
                }
            )
    return lines


@api_bp.route("/events/<event_id>/detail-modal")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_DEFAULT", "120 per minute"))
def event_detail_modal(event_id):
    """Return full event detail HTML for the modal overlay.

    Includes event metadata, geo info, and the complete surrounding
    log context with all lines rendered.
    """
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        row = db.execute(
            "SELECT event_id, timestamp, node_id, source_ip, event_type, "
            "action_taken, metadata, geo_country, geo_asn, geo_org, geo_data "
            "FROM events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
    finally:
        db.close()

    if not row:
        return '<div class="event-modal-loading">Event not found.</div>', 404

    # Backfill geo data if missing (event was ingested before GeoIP DB existed)
    if row["source_ip"] and not row["geo_country"] and not row["geo_data"]:
        looked_up = geo_lookup(row["source_ip"])
        if looked_up.get("country"):
            try:
                _db2 = get_db(current_app.config["DATABASE_PATH"])
                _db2.execute(
                    "UPDATE events SET geo_country=?, geo_asn=?, geo_org=?, geo_data=? WHERE event_id=?",
                    (
                        looked_up.get("country", ""),
                        str(looked_up.get("asn")) if looked_up.get("asn") else None,
                        looked_up.get("org", ""),
                        json.dumps(looked_up),
                        event_id,
                    ),
                )
                _db2.close()
                # Re-read the row so the code below picks up the new values
                _db3 = get_db(current_app.config["DATABASE_PATH"])
                row = _db3.execute(
                    "SELECT event_id, timestamp, node_id, source_ip, event_type, "
                    "action_taken, metadata, geo_country, geo_asn, geo_org, geo_data "
                    "FROM events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                _db3.close()
            except Exception:
                pass

    # Resolve node_id to display name
    node_label = row["node_id"] or ""
    try:
        _db = get_db(current_app.config["DATABASE_PATH"])
        _n = _db.execute(
            "SELECT display_name FROM nodes WHERE node_id = ?", (row["node_id"],)
        ).fetchone()
        if _n and _n["display_name"]:
            node_label = f"{_n['display_name']} ({row['node_id']})"
        _db.close()
    except Exception:
        pass

    # Parse metadata
    meta = row["metadata"]
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except (json.JSONDecodeError, TypeError):
            meta = {}
    if not isinstance(meta, dict):
        meta = {}

    # Geo info
    geo_data = row["geo_data"]
    if isinstance(geo_data, str):
        try:
            geo_data = json.loads(geo_data)
        except (json.JSONDecodeError, TypeError):
            geo_data = {}
    if not isinstance(geo_data, dict):
        geo_data = {}

    geo_country = row["geo_country"] or geo_data.get("country", "")
    geo_asn = row["geo_asn"] or geo_data.get("asn", "")
    geo_org = row["geo_org"] or geo_data.get("org", "")

    # Get log context
    db = get_db(db_path)
    try:
        context_lines = get_event_context(db, event_id)
    finally:
        db.close()

    if not context_lines:
        # Fallback to inline metadata
        inline = meta.get("surrounding_logs")
        if inline:
            context_lines = _parse_inline_context(inline)

    # Build modal HTML
    parts = []

    # -- Event metadata section --
    parts.append('<div class="event-modal-section">')
    parts.append('<div class="event-modal-section-title">Event Information</div>')
    parts.append('<div class="event-modal-meta">')

    meta_items = [
        ("Event ID", f"<code>{_escape_html(row['event_id'])}</code>"),
        ("Timestamp", _escape_html(row["timestamp"] or "")),
        ("Node", f"<code>{_escape_html(node_label)}</code>"),
        (
            "Source IP",
            f'<a href="#" class="ip-intel-link" onclick="event.preventDefault(); openIpIntelModal(\'{_escape_html(row["source_ip"] or "")}\')" title="View IP intelligence"><code>{_escape_html(row["source_ip"] or "")}</code></a>',
        ),
        ("Event Type", f'<span class="badge">{_escape_html(row["event_type"] or "")}</span>'),
        (
            "Action",
            f'<span class="badge badge-action-{_escape_html((row["action_taken"] or "").lower())}">{_escape_html(row["action_taken"] or "")}</span>',
        ),
    ]

    if geo_country:
        meta_items.append(("Country", _escape_html(geo_country)))
    if geo_asn:
        meta_items.append(("ASN", f"AS{_escape_html(str(geo_asn))}"))
    if geo_org:
        meta_items.append(("Organization", _escape_html(geo_org)))

    # Add relevant metadata fields
    skip_keys = {"surrounding_logs", "parser", "matched_rules"}
    for key, value in meta.items():
        if key in skip_keys or value is None:
            continue
        label = key.replace("_", " ").title()
        if isinstance(value, (list, dict)):
            val_str = f"<code>{_escape_html(json.dumps(value))}</code>"
        else:
            val_str = f"<code>{_escape_html(str(value))}</code>"
        meta_items.append((label, val_str))

    for label, value in meta_items:
        parts.append(
            f'<div class="event-modal-meta-item">'
            f'<span class="event-modal-meta-label">{_escape_html(label)}</span>'
            f'<span class="event-modal-meta-value">{value}</span>'
            f"</div>"
        )

    parts.append("</div></div>")  # close meta grid + section

    # -- Log context section --
    if context_lines:
        total_count = sum(ln.get("repeat", 1) for ln in context_lines)
        parts.append('<div class="event-modal-section">')
        parts.append(
            f'<div class="event-modal-section-title">Surrounding Log Context ({total_count} lines)</div>'
        )
        parts.append('<pre class="event-modal-log-lines">')
        for ln in context_lines:
            raw = ln["raw"]
            repeat = ln.get("repeat", 1)
            is_trigger = ln.get("is_trigger", False)
            prefix = f"<b>×{repeat}</b>  " if repeat > 1 else ""
            cls = ' class="log-line-trigger"' if is_trigger else ""
            parts.append(f"<span{cls}>{prefix}{_escape_html(raw)}</span>\n")
        parts.append("</pre>")
        parts.append('<div class="event-modal-actions">')
        parts.append(
            f'<button class="btn btn-sm btn-secondary" onclick="copyLogContext(\'{event_id}\')" title="Copy raw log lines to clipboard">📋 Copy Raw</button>'
        )
        parts.append("</div>")
        parts.append("</div>")
    else:
        parts.append('<div class="event-modal-section">')
        parts.append('<div class="event-modal-section-title">Log Context</div>')
        parts.append(
            '<p style="color:var(--text-muted);font-size:0.8rem;">No surrounding log context available for this event.</p>'
        )
        parts.append("</div>")

    return "".join(parts)


@api_bp.route("/events/<event_id>/context-raw")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_DEFAULT", "120 per minute"))
def event_context_raw(event_id):
    """Return raw log context lines as plain text for clipboard copy."""
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        lines = get_event_context(db, event_id)
    finally:
        db.close()

    if not lines:
        db = get_db(db_path)
        try:
            row = db.execute(
                "SELECT metadata FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row:
                meta = row["metadata"]
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except (json.JSONDecodeError, TypeError):
                        meta = {}
                inline = meta.get("surrounding_logs") if isinstance(meta, dict) else None
                if inline:
                    lines = _parse_inline_context(inline)
        finally:
            db.close()

    if not lines:
        return "", 200, {"Content-Type": "text/plain"}

    output = []
    for ln in lines:
        raw = ln["raw"]
        repeat = ln.get("repeat", 1)
        is_trigger = ln.get("is_trigger", False)
        prefix = f"[x{repeat}] " if repeat > 1 else ""
        marker = ">>> " if is_trigger else "    "
        output.append(f"{marker}{prefix}{raw}")

    return "\n".join(output), 200, {"Content-Type": "text/plain"}


@api_bp.route("/ip/<ip_address>/intel-modal")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_DEFAULT", "120 per minute"))
def ip_intel_modal(ip_address):
    """Return IP intelligence data as HTML for the modal overlay.

    Shows threat score, geo, ASN, sighting history, attack vectors,
    and key timestamps for the given IP address.
    """
    if not current_user.is_authenticated:
        return jsonify({"error": "unauthorized"}), 401

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        record = query_ip_record(db, ip_address)
        vectors = get_attack_vectors(db, ip_address) if record else []
        fleet_block = None
        if record:
            fleet_block = db.execute(
                "SELECT fleet_block_id, status, expires_at, ttl_seconds, "
                "reporting_node_count, originating_node_id "
                "FROM fleet_blocks WHERE source_ip = ? AND status = 'active' "
                "ORDER BY expires_at DESC LIMIT 1",
                (ip_address,),
            ).fetchone()
    finally:
        db.close()

    if not record:
        return (
            '<div class="event-modal-section">'
            '<div class="event-modal-section-title">IP Intelligence</div>'
            f'<p style="color:var(--text-muted);font-size:0.85rem;">No intelligence data found for <code>{_escape_html(ip_address)}</code>.</p>'
            "</div>"
        )

    parts = []

    # -- Header with score --
    score = record.get("reputation_score")
    score_display = f"{score:.0f}/100" if score is not None else "N/A"
    score_class = ""
    if score is not None:
        if score >= 70:
            score_class = "score-high"
        elif score >= 40:
            score_class = "score-medium"
        else:
            score_class = "score-low"

    parts.append('<div class="event-modal-section">')
    parts.append('<div class="event-modal-section-title">IP Intelligence</div>')
    parts.append('<div class="ip-intel-header">')
    parts.append(f'<span class="ip-intel-address"><code>{_escape_html(ip_address)}</code></span>')
    parts.append(
        f'<span class="ip-intel-score {score_class}">Threat Score: <strong>{score_display}</strong></span>'
    )
    if record.get("repeat_offender"):
        parts.append('<span class="badge badge-danger">Repeat Offender</span>')
    parts.append("</div>")

    # -- Fleet Block Status --
    if fleet_block:
        expires_at = fleet_block["expires_at"] or ""
        node_count = fleet_block["reporting_node_count"] or 1
        rem_str = ""
        if expires_at:
            try:
                expires_dt = _parse_db_timestamp(expires_at)
                if expires_dt:
                    remaining = (expires_dt - datetime.now(UTC)).total_seconds()
                    if remaining > 0:
                        if remaining >= 86400:
                            rem_str = f"expires in {int(remaining / 86400)}d {int((remaining % 86400) / 3600)}h"
                        elif remaining >= 3600:
                            rem_str = f"expires in {int(remaining / 3600)}h {int((remaining % 3600) / 60)}m"
                        elif remaining >= 60:
                            rem_str = f"expires in {int(remaining / 60)}m {int(remaining % 60)}s"
                        else:
                            rem_str = f"expires in {int(remaining)}s"
                    else:
                        rem_str = "expiring now"
                else:
                    rem_str = f"expires {expires_at}"
            except (ValueError, TypeError):
                rem_str = f"expires {expires_at}"
        parts.append('<div style="margin-top:0.4rem;">')
        parts.append(
            '<span class="badge badge-fleet" style="font-size:0.85rem;padding:0.35rem 0.65rem;">'
        )
        parts.append(f"Fleet Block Active — {rem_str}")
        parts.append("</span>")
        if node_count > 1:
            parts.append(
                f' <span class="badge badge-info" style="font-size:0.8rem;">reported by {node_count} nodes</span>'
            )
        parts.append("</div>")
    parts.append("</div>")

    # -- Key metrics --
    parts.append('<div class="event-modal-section">')
    parts.append('<div class="event-modal-section-title">Activity Summary</div>')
    parts.append('<div class="event-modal-meta">')

    meta_items = [
        ("Times Seen", str(record.get("total_times_seen", 0))),
        ("Times Blocked", str(record.get("total_times_blocked", 0))),
        ("Attack Events", str(record.get("total_attack_events", 0))),
        ("Reporting Nodes", str(record.get("total_reporting_nodes", 0))),
    ]

    # Recency counters
    if record.get("times_seen_last_24h") is not None:
        meta_items.append(("Last 24h", str(record["times_seen_last_24h"])))
    if record.get("times_seen_last_7d") is not None:
        meta_items.append(("Last 7d", str(record["times_seen_last_7d"])))
    if record.get("times_seen_last_30d") is not None:
        meta_items.append(("Last 30d", str(record["times_seen_last_30d"])))

    for label, value in meta_items:
        parts.append(
            f'<div class="event-modal-meta-item">'
            f'<span class="event-modal-meta-label">{_escape_html(label)}</span>'
            f'<span class="event-modal-meta-value"><strong>{_escape_html(value)}</strong></span>'
            f"</div>"
        )

    parts.append("</div></div>")

    # -- Geo & Network --
    parts.append('<div class="event-modal-section">')
    parts.append('<div class="event-modal-section-title">Network Information</div>')
    parts.append('<div class="event-modal-meta">')

    net_items = [
        ("IP Version", record.get("ip_version", "").upper()),
        ("Country", record.get("geo_country") or "—"),
        ("ASN", f"AS{record['asn']}" if record.get("asn") else "—"),
        ("Organization", record.get("isp_organization") or "—"),
    ]

    for label, value in net_items:
        parts.append(
            f'<div class="event-modal-meta-item">'
            f'<span class="event-modal-meta-label">{_escape_html(label)}</span>'
            f'<span class="event-modal-meta-value">{_escape_html(value)}</span>'
            f"</div>"
        )

    parts.append("</div></div>")

    # -- Timestamps --
    parts.append('<div class="event-modal-section">')
    parts.append('<div class="event-modal-section-title">Timeline</div>')
    parts.append('<div class="event-modal-meta">')

    ts_items = [
        ("First Seen", record.get("first_seen_at") or "—"),
        ("Last Seen", record.get("last_seen_at") or "—"),
        ("Last Blocked", record.get("last_blocked_at") or "—"),
    ]

    for label, value in ts_items:
        parts.append(
            f'<div class="event-modal-meta-item">'
            f'<span class="event-modal-meta-label">{_escape_html(label)}</span>'
            f'<span class="event-modal-meta-value"><span data-ts="{_escape_html(value)}">{_escape_html(value)}</span></span>'
            f"</div>"
        )

    parts.append("</div></div>")

    # -- Threat Tags --
    tags = record.get("threat_tags", [])
    if tags:
        parts.append('<div class="event-modal-section">')
        parts.append('<div class="event-modal-section-title">Threat Tags</div>')
        parts.append('<div class="ip-intel-tags">')
        for tag in tags:
            parts.append(f'<span class="badge badge-parser">{_escape_html(tag)}</span>')
        parts.append("</div></div>")

    # -- Attack Vectors --
    if vectors:
        parts.append('<div class="event-modal-section">')
        parts.append('<div class="event-modal-section-title">Attack Vectors</div>')
        parts.append(
            '<table class="ip-intel-vectors-table"><thead><tr><th>Detection Rule</th><th>Count</th></tr></thead><tbody>'
        )
        for v in vectors[:10]:
            rule = _escape_html(v["detection_rule"])
            count = v["fire_count"]
            parts.append(f"<tr><td><code>{rule}</code></td><td>{count}</td></tr>")
        parts.append("</tbody></table>")
        parts.append("</div>")

    # -- Reporting Nodes --
    nodes = record.get("reporting_node_list", [])
    if nodes:
        node_names = _resolve_node_display_names(nodes)
        parts.append('<div class="event-modal-section">')
        parts.append('<div class="event-modal-section-title">Reporting Nodes</div>')
        parts.append('<div class="ip-intel-tags">')
        for node_id, display in node_names[:20]:
            if display:
                parts.append(
                    f'<span class="badge" title="{_escape_html(node_id)}">{_escape_html(display)}</span>'
                )
            else:
                parts.append(f'<span class="badge">{_escape_html(node_id)}</span>')
        parts.append("</div></div>")

    return "".join(parts)


@api_bp.route("/nodes/<node_id>/commands")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_COMMANDS", "60 per minute"))
def node_commands(node_id):
    """Command channel for nodes to poll for pending commands.

    Nodes call this endpoint periodically (e.g. alongside heartbeat) to
    pick up queued commands like allowlist_add, allowlist_remove, block,
    unblock. Returns pending commands and marks them as acknowledged.

    Requires Bearer token authentication.

    Requirements: 16.1
    """
    api_key, error_response = _authenticate_api_key()
    if error_response is not None:
        return error_response

    # Enforce node_id restriction
    node_id_restriction = api_key.get("node_id_restriction")
    if node_id_restriction and node_id != node_id_restriction:
        return jsonify(
            {
                "error": "node_id_mismatch",
                "message": f"API key is restricted to node '{node_id_restriction}'",
            }
        ), 403

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        commands = get_pending_commands(db, node_id)

        # Mark each command as acknowledged
        for cmd in commands:
            acknowledge_command(db, cmd["command_id"], status="acknowledged")

        update_last_seen(db, node_id)
    finally:
        db.close()

    # Return commands in a format the node can process
    result = []
    for cmd in commands:
        payload = cmd.get("payload", "{}")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                payload = {}
        result.append(
            {
                "command_id": cmd["command_id"],
                "command_type": cmd["command_type"],
                "payload": payload,
            }
        )

    return jsonify({"commands": result}), 200


@api_bp.route("/nodes/<node_id>/commands/<command_id>/result", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_COMMANDS", "60 per minute"))
def command_result(node_id, command_id):
    """Report the result of a command execution.

    Nodes call this after processing a command to report success or failure.

    Request body (JSON):
        {
            "status": "completed" | "failed",
            "result": "optional message"
        }
    """
    api_key, error_response = _authenticate_api_key()
    if error_response is not None:
        return error_response

    node_id_restriction = api_key.get("node_id_restriction")
    if node_id_restriction and node_id != node_id_restriction:
        return jsonify(
            {
                "error": "node_id_mismatch",
                "message": f"API key is restricted to node '{node_id_restriction}'",
            }
        ), 403

    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_json"}), 400

    status = body.get("status", "completed")
    if status not in ("completed", "failed"):
        return jsonify(
            {"error": "invalid_status", "message": "Must be 'completed' or 'failed'"}
        ), 400

    result_msg = body.get("result", "")

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        found = acknowledge_command(db, command_id, status=status, result=result_msg)
        update_last_seen(db, node_id)
    finally:
        db.close()

    if not found:
        return jsonify({"error": "not_found", "message": "Command not found"}), 404

    return jsonify({"ok": True}), 200


@api_bp.route("/heartbeat", methods=["POST"])
@limiter.limit(
    lambda: current_app.config.get("RATELIMIT_HEARTBEAT", "30 per minute"),
    key_func=_key_func_body_node,
)
def heartbeat():
    """Node heartbeat endpoint.

    Nodes POST a heartbeat every few minutes to keep their health status
    as 'healthy' on the dashboard even when there are no security events
    to ship. Updates last_event_at on the node without incrementing
    total_events.

    Request body (JSON):
        {
            "node_id": "web01-abc123",
            "timestamp": "2025-01-15T10:30:00Z",
            "geo_data": {"country": "US"}   // optional
        }
    """
    # Authenticate
    api_key, error_response = _authenticate_api_key()
    if error_response is not None:
        return error_response

    # Parse JSON body
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    if body is None or not isinstance(body, dict):
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    node_id = body.get("node_id", "")
    timestamp = body.get("timestamp", "")
    display_name = body.get("display_name", "")

    if not node_id or not isinstance(node_id, str):
        return jsonify({"error": "missing_node_id", "message": "node_id is required"}), 400

    if not timestamp or not isinstance(timestamp, str):
        return jsonify({"error": "missing_timestamp", "message": "timestamp is required"}), 400

    # Enforce node_id restriction if the API key has one
    node_id_restriction = api_key.get("node_id_restriction")
    if node_id_restriction and node_id != node_id_restriction:
        return jsonify(
            {
                "error": "node_id_mismatch",
                "message": f"API key is restricted to node '{node_id_restriction}'",
            }
        ), 403

    geo_data = body.get("geo_data")

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        touch_node(db, node_id, timestamp, geo_data)
        update_last_seen(db, node_id)
        if display_name and isinstance(display_name, str) and display_name.strip():
            dn = display_name.strip()
            db.execute(
                "UPDATE nodes SET display_name = ? WHERE node_id = ? AND display_name != ?",
                (dn, node_id, dn),
            )
            db.commit()
        update_api_key_last_used(db, api_key["id"])

        # Store node state snapshots if provided in the heartbeat
        snapshot_fields = {
            "allowlist": "last_allowlist",
            "feeds": "last_feeds",
            "counters": "last_counters",
            "host_info": "last_host_info",
        }
        updates = []
        params = []
        for body_key, col_name in snapshot_fields.items():
            value = body.get(body_key)
            if value is not None:
                updates.append(f"{col_name} = ?")
                params.append(json.dumps(value) if not isinstance(value, str) else value)
        if updates:
            params.append(node_id)
            db.execute(
                f"UPDATE nodes SET {', '.join(updates)} WHERE node_id = ?",
                params,
            )
            db.commit()

        # Store agent version if provided
        agent_version = body.get("agent_version")
        if agent_version and isinstance(agent_version, str):
            db.execute(
                "UPDATE nodes SET agent_version = ? WHERE node_id = ?",
                (agent_version, node_id),
            )
            db.commit()

        # Persist counter snapshots for historical tracking
        counters = body.get("counters")
        if counters and isinstance(counters, list):
            insert_counter_snapshots(db, node_id, timestamp, counters)

        # Update asset from heartbeat data
        asset_id = body.get("asset_id", "") or ""
        host_info = body.get("host_info", {}) or {}
        if asset_id:
            update_asset_seen(db, asset_id, host_info)
            db.execute(
                "UPDATE nodes SET asset_id = ? WHERE node_id = ? AND (asset_id IS NULL OR asset_id = '')",
                (asset_id, node_id),
            )
            db.commit()
        elif host_info.get("machine_id"):
            machine_id = host_info.get("machine_id", "").strip()
            hostname = host_info.get("hostname", "") or display_name
            ifaces = host_info.get("interfaces") or []
            ids = {"hostname": hostname, "machine_id": machine_id}
            for iface in ifaces if isinstance(ifaces, list) else []:
                if isinstance(iface, dict):
                    mac = iface.get("mac", "") or ""
                    if mac.strip():
                        ids.setdefault("mac", []).append(mac.strip())
                    for ip in iface.get("ipv4", []):
                        if ip and isinstance(ip, str) and ip.strip():
                            ids.setdefault("ipv4", []).append(ip.strip())
            resolved_id = ensure_asset(
                db,
                asset_type="host",
                display_name=hostname,
                source="agent",
                metadata=host_info,
                **ids,
            )
            db.execute("UPDATE nodes SET asset_id = ? WHERE node_id = ?", (resolved_id, node_id))
            db.execute(
                "UPDATE enrollment_requests SET asset_id = ? WHERE node_id = ? AND (asset_id IS NULL OR asset_id = '')",
                (resolved_id, node_id),
            )
            db.commit()

        # Fetch fleet-wide active block count to return to the node
        try:
            fleet_active_row = db.execute(
                "SELECT COUNT(*) as cnt FROM fleet_blocks WHERE status = 'active'"
            ).fetchone()
            fleet_active_blocks = fleet_active_row["cnt"] if fleet_active_row else 0
        except Exception:
            logger.exception("Failed to query fleet_active_blocks for heartbeat")
            fleet_active_blocks = 0
    finally:
        db.close()

    return jsonify(
        {
            "ok": True,
            "node_id": node_id,
            "fleet_active_blocks": fleet_active_blocks,
        }
    ), 200


# ---------------------------------------------------------------------------
# Node Blocks Publish — daemon pushes block list here
# ---------------------------------------------------------------------------


@api_bp.route("/nodes/blocks/publish", methods=["POST"])
@limiter.limit("30 per minute")
def publish_blocks():
    """Receive the daemon's current block list and reconcile into node_blocks.

    The daemon calls this endpoint when its local block list changes.
    The endpoint replaces all entries for the given node_id with the
    provided list in a single transaction.
    """
    api_key, error_response = _authenticate_api_key()
    if error_response is not None:
        return error_response

    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    if not isinstance(body, dict):
        return jsonify({"error": "invalid_json"}), 400

    node_id = body.get("node_id", "")
    blocks = body.get("blocks", [])

    if not node_id or not isinstance(node_id, str):
        return jsonify({"error": "missing_node_id"}), 400
    if not isinstance(blocks, list):
        return jsonify({"error": "invalid_blocks"}), 400

    # Enforce node_id restriction if the API key has one
    node_id_restriction = api_key.get("node_id_restriction")
    if node_id_restriction and node_id != node_id_restriction:
        return jsonify({"error": "node_id_mismatch"}), 403

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        db.execute("DELETE FROM node_blocks WHERE node_id = ?", (node_id,))
        for entry in blocks:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip", "")
            if not ip:
                continue
            db.execute(
                "INSERT INTO node_blocks (node_id, ip, reason, blocked_at, expires_at, strike) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    node_id,
                    ip,
                    entry.get("reason", ""),
                    entry.get("blocked_at") or entry.get("added_at", 0),
                    entry.get("expires_at", 0),
                    entry.get("strike") or entry.get("offenses", 1),
                ),
            )
        db.commit()
        return jsonify({"ok": True, "count": len(blocks)}), 200
    except Exception:
        logger.exception("Failed to publish blocks for node %s", node_id)
        return jsonify({"error": "internal_error", "message": "An internal error occurred"}), 500
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Unlock Webhook — simple secret-based unblock for emergency access
# ---------------------------------------------------------------------------


@api_bp.route("/unlock-webhook/<ip>", methods=["POST"])
@limiter.limit("10 per minute")
def unlock_webhook(ip: str):
    """Unblock an IP via a pre-shared secret webhook.

    URL format: POST /api/v1/unlock-webhook/<ip>

    The pre-shared secret is passed in the X-Unlock-Secret request header
    (never in the URL — URL paths leak into access logs, proxies, and
    browser history).  It is compared in constant time against the
    ``unlock_webhook_secret`` value stored in fleet_config (set via the
    Fleet Configuration page).

    Returns 200 on success, 403 for bad secret, 404 if no block found.
    """
    # Validate IP format
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "invalid_ip", "message": f"'{ip}' is not a valid IP address"}), 400

    secret = (request.headers.get("X-Unlock-Secret") or "").strip()

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        row = db.execute(
            "SELECT config_value FROM fleet_config WHERE config_key = 'unlock_webhook_secret'"
        ).fetchone()
        stored_secret = row["config_value"].strip() if row else ""
    finally:
        db.close()

    if not stored_secret:
        return jsonify(
            {"error": "not_configured", "message": "Unlock webhook secret is not configured"}
        ), 501

    if not hmac.compare_digest(secret.encode(), stored_secret.encode()):
        return jsonify({"error": "forbidden", "message": "Invalid secret"}), 403

    engine = current_app.propagation_engine
    result = engine.manual_remove(ip, actor="webhook")

    if result["status"] == "not_found":
        return jsonify(result), 404

    # Audit
    db = get_db(db_path)
    try:
        record_audit(
            db,
            actor="webhook",
            actor_ip=request.remote_addr or "unknown",
            action_type="webhook_unblock",
            target=ip,
            details={"result": result.get("status")},
        )
        db.commit()
    finally:
        db.close()

    return jsonify(result), 200

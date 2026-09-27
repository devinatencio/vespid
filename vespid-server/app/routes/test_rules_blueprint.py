"""Test Rules blueprint — dry-run simulation page for rule validation.

Provides the admin-only Test Rule Page where administrators can upload
log files and run them through selected detection rule packs in a
side-effect-free simulation. Results are streamed via a single HTTP
POST that returns ``text/event-stream`` — this keeps the simulation
worker thread and the SSE response on the same worker process, avoiding
the cross-worker race that plagued the prior two-step (POST + EventSource)
flow.

Endpoints:
    GET  /admin/test-rules                  — Render the test rule page
    POST /admin/test-rules/run              — Stream simulation results via SSE
    POST /admin/test-rules/cancel/<sim_id>  — Cancel a running simulation

Requirements: 2.1, 2.3, 2.4, 2.5, 2.6, 2.7, 3.4, 3.5, 3.6, 5.3, 5.4, 7.1, 7.2, 7.3
"""

import json
import logging
import queue
import threading
import time
import uuid

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    render_template,
    request,
)

from app.decorators import require_role
from app.models import get_db
from app.pack_loader import get_pack_metadata, load_packs
from app.test_rules import (
    BruteForceRule,
    CorrelationRule,
    CustomRule,
    SimulationEngine,
    SimulationResult,
    SimulationSSEManager,
    detect_log_format,
    validate_file_extension,
)

logger = logging.getLogger(__name__)

test_rules_bp = Blueprint(
    "test_rules",
    __name__,
    url_prefix="/admin/test-rules",
)

# Maximum file size: 10 MB
_MAX_FILE_SIZE = 10 * 1024 * 1024

# Maximum concurrent simulations per server instance
_MAX_CONCURRENT_SIMULATIONS = 3

# Simulation timeout in seconds (auto-cancels if exceeded)
_SIMULATION_TIMEOUT_SECONDS = 60

# TTL for simulation entries (5 minutes)
_SIMULATION_TTL_SECONDS = 300

# Max buffered progress events in the per-request queue
_PROGRESS_QUEUE_MAXSIZE = 1000

# Keepalive interval — sent as an SSE comment if no event for this many seconds
_KEEPALIVE_SECONDS = 15


# ===========================================================================
# Helpers
# ===========================================================================


def _get_simulations() -> dict:
    """Get or initialize the app-level simulations registry.

    Returns a dict mapping simulation_id -> {
        "engine": SimulationEngine | None,
        "created_at": float (time.time()),
        "finished": bool,
        "result": SimulationResult | None,
    }
    """
    if not hasattr(current_app, "simulations"):
        current_app.simulations = {}
    return current_app.simulations


def _count_active_simulations() -> int:
    """Count currently running (not finished) simulations on this worker."""
    simulations = _get_simulations()
    return sum(1 for s in simulations.values() if not s.get("finished", False))


def _cleanup_expired_simulations() -> None:
    """Remove simulation entries older than the TTL."""
    simulations = _get_simulations()
    now = time.time()
    expired_ids = [
        sim_id
        for sim_id, sim_data in simulations.items()
        if now - sim_data["created_at"] > _SIMULATION_TTL_SECONDS
    ]
    for sim_id in expired_ids:
        simulations.pop(sim_id, None)


def _load_rules_for_simulation(selected_pack_names: list, selected_rule_ids: list) -> tuple:
    """Load brute force rules, custom rules, and correlation rules for the simulation.

    Args:
        selected_pack_names: List of pack_name strings to include.
        selected_rule_ids: List of individual brute force rule IDs (as strings).

    Returns:
        A tuple of (brute_force_rules, custom_rules, correlation_rules) ready for SimulationEngine.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    brute_force_rules = []
    custom_rules = []
    correlation_rules = []

    try:
        # Load rules from selected packs
        if selected_pack_names:
            placeholders = ",".join("?" * len(selected_pack_names))
            # Custom rules from packs (templates)
            cr_rows = db.execute(
                f"SELECT name, event_type, regex, log_sources, max_attempts, "
                f"window_seconds, tags, sigma_id, sigma_status "
                f"FROM detection_rules_custom "
                f"WHERE is_template = 1 AND pack_name IN ({placeholders})",
                selected_pack_names,
            ).fetchall()

            for r in cr_rows:
                log_sources = r["log_sources"]
                if isinstance(log_sources, str):
                    try:
                        log_sources = json.loads(log_sources)
                    except (json.JSONDecodeError, TypeError):
                        log_sources = ["*"]
                tags = r["tags"]
                if isinstance(tags, str):
                    try:
                        tags = json.loads(tags)
                    except (json.JSONDecodeError, TypeError):
                        tags = []
                custom_rules.append(
                    CustomRule(
                        name=r["name"],
                        event_type=r["event_type"],
                        regex=r["regex"],
                        log_sources=log_sources,
                        max_attempts=r["max_attempts"],
                        window_seconds=r["window_seconds"],
                        enabled=True,
                        tags=tags,
                        sigma_id=r["sigma_id"] or "",
                        sigma_status=r["sigma_status"] or "",
                    )
                )

        # Load individually selected brute force rules
        if selected_rule_ids:
            placeholders = ",".join("?" * len(selected_rule_ids))
            bf_rows = db.execute(
                f"SELECT name, event_type, max_attempts, window_seconds, parser "
                f"FROM detection_rules_brute_force "
                f"WHERE id IN ({placeholders})",
                selected_rule_ids,
            ).fetchall()

            for r in bf_rows:
                brute_force_rules.append(
                    BruteForceRule(
                        name=r["name"],
                        event_type=r["event_type"],
                        max_attempts=r["max_attempts"],
                        window_seconds=r["window_seconds"],
                        parser=r["parser"],
                    )
                )

        # Always load enabled correlation rules — they apply across all parsers
        corr_rows = db.execute(
            "SELECT name, event_type, min_categories, window_seconds "
            "FROM detection_rules_correlation WHERE enabled = 1 ORDER BY name"
        ).fetchall()
        for r in corr_rows:
            correlation_rules.append(
                CorrelationRule(
                    name=r["name"],
                    event_type=r["event_type"],
                    min_categories=r["min_categories"],
                    window_seconds=r["window_seconds"],
                    enabled=True,
                )
            )

    finally:
        db.close()

    return brute_force_rules, custom_rules, correlation_rules


def _parse_simulation_inputs() -> tuple[dict | None, tuple | None]:
    """Parse and validate the POST form for a simulation request.

    Returns:
        On success: (inputs_dict, None) where inputs_dict contains the keys
            ``log_lines``, ``brute_force_rules``, ``custom_rules``,
            ``correlation_rules``, and ``detected_parser``.
        On failure: (None, (json_response, status_code)).
    """
    # Get selected packs and rules
    selected_packs = request.form.getlist("selected_packs")
    selected_rules = request.form.getlist("selected_rules")

    if not selected_packs and not selected_rules:
        return None, (
            jsonify({"error": "At least one pack or rule must be selected."}),
            422,
        )

    # Get log content — either from file upload or text area
    log_file = request.files.get("log_file")
    log_text = request.form.get("log_text", "").strip()
    log_content = None

    if log_file and log_file.filename:
        # Validate file extension
        if not validate_file_extension(log_file.filename):
            return None, (
                jsonify(
                    {
                        "error": "Invalid file extension. Accepted: .log, .txt, or no extension.",
                    }
                ),
                422,
            )

        # Read file content
        raw_bytes = log_file.read()

        # Validate file size
        if len(raw_bytes) > _MAX_FILE_SIZE:
            return None, (
                jsonify({"error": "File exceeds maximum size of 10 MB."}),
                422,
            )

        # Validate non-empty
        if len(raw_bytes) == 0:
            return None, (
                jsonify(
                    {
                        "error": "File is empty. Please upload a file with at least one line.",
                    }
                ),
                422,
            )

        # Validate UTF-8 encoding
        try:
            log_content = raw_bytes.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return None, (
                jsonify(
                    {
                        "error": "File is not valid UTF-8 text. Only text-encoded files are supported.",
                    }
                ),
                422,
            )

    elif log_text:
        # Validate text area size
        if len(log_text.encode("utf-8")) > _MAX_FILE_SIZE:
            return None, (
                jsonify({"error": "Text content exceeds maximum size of 10 MB."}),
                422,
            )
        log_content = log_text
    else:
        return None, (
            jsonify({"error": "No log file or text content provided."}),
            422,
        )

    # Split into lines
    log_lines = log_content.splitlines()
    if not log_lines:
        return None, (
            jsonify({"error": "Log content is empty (no lines found)."}),
            422,
        )

    # Determine parser
    parser_override = request.form.get("parser_override", "auto").strip()
    if parser_override and parser_override != "auto":
        detected_parser = parser_override
    else:
        detected_parser, _counts = detect_log_format(log_lines)
        if detected_parser is None:
            # Default to "secure" if no format detected — user can override
            detected_parser = "secure"

    # Load rules for the simulation
    brute_force_rules, custom_rules, correlation_rules = _load_rules_for_simulation(
        selected_packs, selected_rules
    )

    if not brute_force_rules and not custom_rules and not correlation_rules:
        return None, (
            jsonify({"error": "No rules found for the selected packs/rules."}),
            422,
        )

    return (
        {
            "log_lines": log_lines,
            "brute_force_rules": brute_force_rules,
            "custom_rules": custom_rules,
            "correlation_rules": correlation_rules,
            "detected_parser": detected_parser,
        },
        None,
    )


def _serialize_simulation_result(result: SimulationResult) -> dict:
    """Convert a SimulationResult into a JSON-serializable dict for the client."""
    detections_data = [
        {
            "rule_name": d.rule_name,
            "event_type": d.event_type,
            "source_ip": d.source_ip,
            "attempt_count": d.attempt_count,
            "window_seconds": d.window_seconds,
            "triggered_at_line": d.triggered_at_line,
            "order": d.order,
            "matched_lines": [
                {
                    "line_number": ml.line_number,
                    "raw_line": ml.raw_line,
                    "category": ml.category,
                }
                for ml in d.matched_lines
            ],
        }
        for d in result.detections
    ]

    per_rule_data = [
        {
            "rule_name": entry["rule_name"],
            "trigger_count": entry["trigger_count"],
            "distinct_ips": (
                len(entry["distinct_ips"])
                if isinstance(entry["distinct_ips"], set)
                else entry["distinct_ips"]
            ),
        }
        for entry in result.per_rule_breakdown
    ]

    per_ip_data = [
        {
            "source_ip": entry["source_ip"],
            "match_count": entry["match_count"],
            "rules_fired": (
                list(entry["rules_fired"])
                if isinstance(entry["rules_fired"], set)
                else entry["rules_fired"]
            ),
        }
        for entry in result.per_ip_breakdown
    ]

    per_rule_match_data = [
        {
            "rule_name": entry["rule_name"],
            "match_count": entry["match_count"],
            "distinct_ips": (
                len(entry["distinct_ips"])
                if isinstance(entry["distinct_ips"], set)
                else entry["distinct_ips"]
            ),
        }
        for entry in result.per_rule_matches
    ]

    return {
        "simulation_id": result.simulation_id,
        "total_lines": result.total_lines,
        "lines_processed": result.lines_processed,
        "total_matches": result.total_matches,
        "total_detections": result.total_detections,
        "unique_ips": len(result.unique_ips),
        "elapsed_seconds": round(result.elapsed_seconds, 2),
        "skipped_lines": result.skipped_lines,
        "detected_parser": result.detected_parser,
        "cancelled": result.cancelled,
        "detections": detections_data,
        "per_rule_breakdown": per_rule_data,
        "per_ip_breakdown": per_ip_data,
        "per_rule_matches": per_rule_match_data,
        "total_rules": result.total_rules,
    }


# ===========================================================================
# Routes
# ===========================================================================


@test_rules_bp.route("", methods=["GET"])
@require_role("admin")
def index():
    """Render the test rule page.

    Displays available packs, standalone brute force rules, and the
    file upload / text area form.

    Requirements: 7.1, 7.2, 7.3
    """
    # Load packs for display
    packs = load_packs()
    pack_metadata = get_pack_metadata(packs)

    # Load standalone brute force rules (not in any pack)
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        bf_rows = db.execute(
            "SELECT id, name, event_type, max_attempts, window_seconds, parser, enabled "
            "FROM detection_rules_brute_force WHERE enabled = 1 ORDER BY name"
        ).fetchall()
        standalone_rules = [dict(r) for r in bf_rows]
    finally:
        db.close()

    # Enrich pack metadata with rule counts from the loaded packs
    pack_display = []
    for meta in pack_metadata:
        pack_data = next((p for p in packs if p["pack_name"] == meta["pack_name"]), None)
        rule_count = len(pack_data["rules"]) if pack_data else 0
        pack_display.append(
            {
                **meta,
                "rule_count": rule_count,
            }
        )

    return render_template(
        "admin/test_rules.html",
        packs=pack_display,
        standalone_rules=standalone_rules,
    )


@test_rules_bp.route("/run", methods=["POST"])
@require_role("admin")
def run_simulation():
    """Stream simulation results via Server-Sent Events.

    Validates inputs synchronously and returns JSON with HTTP 4xx on
    error. On success, returns a ``text/event-stream`` Response that
    yields:

    * ``event: started`` — first message; carries ``simulation_id`` and
      ``total_lines`` so the client can render the progress bar.
    * ``event: progress`` — emitted roughly every 100 lines / 500ms
      while the engine is running.
    * ``event: result`` | ``cancelled`` | ``error`` — exactly one
      terminal message; the stream closes after this.

    Because the engine thread, the watchdog, and the SSE generator all
    live on the same worker process, the cross-worker race that
    plagued the prior two-step (POST + EventSource) flow is gone.

    Closing the HTTP connection (browser abort) cancels the engine via
    :class:`GeneratorExit`. Partial results on cancel are best-effort:
    if the cancel endpoint is reachable (same worker) the engine
    publishes a ``cancelled`` event the client can render; otherwise
    the client simply sees the connection close.

    Requirements: 2.1, 2.3, 2.4, 2.5, 2.6, 2.7, 3.4, 3.5, 3.6, 5.3
    """
    # Clean up expired simulations first
    _cleanup_expired_simulations()

    # Check concurrent simulation limit
    if _count_active_simulations() >= _MAX_CONCURRENT_SIMULATIONS:
        return (
            jsonify(
                {
                    "error": "Too many concurrent simulations. Please wait for one to finish.",
                }
            ),
            429,
        )

    # Validate inputs synchronously — error responses are JSON, not SSE
    inputs, error = _parse_simulation_inputs()
    if error is not None:
        return error

    log_lines = inputs["log_lines"]
    detected_parser = inputs["detected_parser"]

    simulation_id = str(uuid.uuid4())

    # Reserve the simulation_id in the per-worker registry so the cancel
    # endpoint can find it. The engine is set inside the generator once
    # the queue is ready.
    sim_entry = {
        "engine": None,
        "created_at": time.time(),
        "finished": False,
        "result": None,
    }
    simulations = _get_simulations()
    simulations[simulation_id] = sim_entry

    def generate():
        """Yield SSE messages as the engine produces them."""
        # Per-request queue bridges the engine thread and the response stream
        progress_queue: queue.Queue = queue.Queue(maxsize=_PROGRESS_QUEUE_MAXSIZE)

        engine = SimulationEngine(
            simulation_id=simulation_id,
            log_lines=log_lines,
            brute_force_rules=inputs["brute_force_rules"],
            custom_rules=inputs["custom_rules"],
            detected_parser=detected_parser,
            correlation_rules=inputs["correlation_rules"],
            progress_queue=progress_queue,
        )
        sim_entry["engine"] = engine

        # Holds the final result/error so the generator can emit it after
        # the worker thread signals completion via a None sentinel.
        terminal: dict[str, object] = {"event": None, "data": None}

        def _run():
            try:
                result = engine.run()
                sim_entry["result"] = result
                sim_entry["finished"] = True
                if result.cancelled:
                    terminal["event"] = "cancelled"
                    terminal["data"] = {
                        "simulation_id": simulation_id,
                        "cancelled": True,
                        "lines_processed": result.lines_processed,
                        "total_lines": result.total_lines,
                        "total_matches": result.total_matches,
                        "total_detections": result.total_detections,
                    }
                else:
                    terminal["event"] = "result"
                    terminal["data"] = _serialize_simulation_result(result)
                    logger.info(
                        "Simulation %s complete: lines=%d matches=%d detections=%d",
                        simulation_id,
                        result.total_lines,
                        result.total_matches,
                        result.total_detections,
                    )
            except Exception:
                logger.exception("Simulation %s crashed", simulation_id)
                sim_entry["finished"] = True
                terminal["event"] = "error"
                terminal["data"] = {"error": "Simulation failed unexpectedly."}
            finally:
                # Wake up the generator (which may be blocked in q.get)
                try:
                    progress_queue.put_nowait(None)
                except queue.Full:
                    pass

        thread = threading.Thread(
            target=_run,
            name=f"sim-{simulation_id[:8]}",
            daemon=True,
        )
        thread.start()

        def _watchdog():
            time.sleep(_SIMULATION_TIMEOUT_SECONDS)
            if not sim_entry.get("finished", False):
                logger.info(
                    "Simulation %s timed out after %ds, auto-cancelling",
                    simulation_id,
                    _SIMULATION_TIMEOUT_SECONDS,
                )
                engine.cancel()

        watchdog = threading.Thread(
            target=_watchdog,
            name=f"sim-watchdog-{simulation_id[:8]}",
            daemon=True,
        )
        watchdog.start()

        # First event: tell the client the simulation is starting and
        # how many lines we'll process (so the progress bar can render
        # correctly even before the first progress event).
        yield SimulationSSEManager._format_sse(
            "started",
            json.dumps(
                {
                    "simulation_id": simulation_id,
                    "total_lines": len(log_lines),
                    "detected_parser": detected_parser,
                }
            ),
        )

        try:
            while True:
                try:
                    msg = progress_queue.get(timeout=_KEEPALIVE_SECONDS)
                except queue.Empty:
                    # No events for _KEEPALIVE_SECONDS — send a comment
                    # to keep proxies / load balancers from idling out
                    # the connection.
                    yield ": keepalive\n\n"
                    continue

                if msg is None:
                    # Worker finished. Emit exactly one terminal event.
                    event = terminal["event"] or "error"
                    data = terminal["data"] or {"error": "Simulation ended without a result."}
                    yield SimulationSSEManager._format_sse(event, json.dumps(data))
                    return

                # msg is a (event_name, payload_dict) tuple from the engine
                event_name, payload = msg
                yield SimulationSSEManager._format_sse(event_name, json.dumps(payload))
        except GeneratorExit:
            # Client disconnected. Signal cancellation so the worker
            # thread doesn't keep churning. The worker will eventually
            # publish a None sentinel and exit on its own.
            logger.info("Simulation %s client disconnected; cancelling engine", simulation_id)
            engine.cancel()
        finally:
            # Free the registry entry as soon as the response is done
            simulations.pop(simulation_id, None)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@test_rules_bp.route("/cancel/<sim_id>", methods=["POST"])
@require_role("admin")
def cancel_simulation(sim_id):
    """Cancel a running simulation.

    Signals the SimulationEngine to stop processing. The engine will
    finish the current line and publish a ``cancelled`` SSE event with
    partial results that the client can render.

    NOTE: This endpoint requires the cancel POST to land on the same
    worker process as the simulation's POST. If it lands on a
    different worker (cross-worker race) it returns 404 and the
    client should fall back to aborting the streaming connection.

    Requirements: 5.4
    """
    simulations = _get_simulations()
    sim_entry = simulations.get(sim_id)

    if sim_entry is None:
        return jsonify({"error": "Simulation not found."}), 404

    engine = sim_entry.get("engine")
    if engine is None or sim_entry.get("finished", False):
        return jsonify({"error": "Simulation already finished."}), 400

    # Signal cancellation
    engine.cancel()

    return jsonify({"status": "cancelling", "simulation_id": sim_id}), 200

"""Intelligence Database service layer.

Orchestrates validation (intel_validators.py) and database operations
(intel_models.py) for sighting submissions, block event submissions,
batch processing, and query operations.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict

from app.geo import lookup as geo_lookup
from app.intel_models import (
    GENERIC_TAGS,
    compute_recency,
    get_ip_record,
    search_ip_records,
    upsert_ip_record,
)
from app.intel_score import compute_threat_score
from app.intel_validators import (
    validate_batch_event,
    validate_batch_request,
    validate_block_event,
    validate_query_params,
    validate_sighting,
)

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised when payload validation fails."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"Validation failed: {errors}")


def _enrich_metadata_with_geo(ip_address: str, metadata: dict) -> dict:
    """Enrich metadata dict with geo information for an IP address.

    Performs a geo lookup and adds country, ASN, and organization data
    to the metadata if available. Does not overwrite existing non-None values.

    Args:
        ip_address: The IPv4 or IPv6 address to look up.
        metadata: The existing metadata dict to enrich.

    Returns:
        The enriched metadata dict (same object, modified in place).
    """
    geo_data = geo_lookup(ip_address)

    # Only add geo fields if they're not already present with non-None values
    if geo_data.get("country") and not metadata.get("geo_country"):
        metadata["geo_country"] = geo_data["country"]
    if geo_data.get("asn") and not metadata.get("asn"):
        metadata["asn"] = geo_data["asn"]
    if geo_data.get("org") and not metadata.get("isp_organization"):
        metadata["isp_organization"] = geo_data["org"]

    return metadata


def process_sighting(db, payload: dict) -> dict:
    """Validate and process a sighting submission.

    Validates the payload using validate_sighting(), then calls
    upsert_ip_record with is_block=False. Returns a summary dict
    with the acceptance status and updated counter.

    Args:
        db: Database connection.
        payload: Sighting payload dict with source_ip, node_id,
            event_type, timestamp, and optional metadata/threat_tag.

    Returns:
        A dict with keys: status, ip_address, total_times_seen.

    Raises:
        ValidationError: If the payload fails validation.
    """
    errors = validate_sighting(payload)
    if errors:
        raise ValidationError(errors)

    source_ip = payload["source_ip"]
    node_id = payload["node_id"]
    event_type = payload["event_type"]
    timestamp = payload["timestamp"]

    # Build metadata from optional fields
    metadata = payload.get("metadata") or {}
    if "threat_tag" in payload and payload["threat_tag"] is not None:
        metadata["threat_tag"] = payload["threat_tag"]

    # Derive threat_tag from event_type if not already present in metadata
    # Uses the same derivation logic as block events: lowercase + replace _ with -
    # (e.g., SSH_BRUTE -> ssh-brute, RECON_CORRELATION -> recon-correlation)
    if not metadata.get("threat_tag"):
        derived_tag = event_type.lower().replace("_", "-")
        # Only set if the derived tag is meaningful (non-empty after strip)
        # and not in the generic tags blocklist (Req 20, AC 3)
        if derived_tag and derived_tag.strip() and derived_tag not in GENERIC_TAGS:
            metadata["threat_tag"] = derived_tag

    # Enrich with geo data (country, ASN, organization)
    metadata = _enrich_metadata_with_geo(source_ip, metadata)

    # Extract request_count from metadata (default 1 if not provided)
    request_count = metadata.get("request_count", 1)
    if not isinstance(request_count, int) or request_count < 1:
        request_count = 1

    event_id = metadata.get("event_id", "") if isinstance(metadata, dict) else ""

    record = upsert_ip_record(
        conn=db,
        ip_address=source_ip,
        node_id=node_id,
        event_type=event_type,
        timestamp=timestamp,
        is_block=False,
        metadata=metadata,
        request_count=request_count,
        event_id=event_id,
    )

    return {
        "status": "accepted",
        "ip_address": record["ip_address"],
        "total_times_seen": record["total_times_seen"],
    }


def process_block_event(db, payload: dict) -> dict:
    """Validate and process a block event submission.

    Validates the payload using validate_block_event(), then calls
    upsert_ip_record with is_block=True. Returns a summary dict
    with the acceptance status and updated counters.

    Args:
        db: Database connection.
        payload: Block event payload dict with source_ip, node_id,
            event_type, detection_rule, block_ttl_seconds, timestamp.

    Returns:
        A dict with keys: status, ip_address, total_times_seen,
        total_times_blocked.

    Raises:
        ValidationError: If the payload fails validation.
    """
    errors = validate_block_event(payload)
    if errors:
        raise ValidationError(errors)

    source_ip = payload["source_ip"]
    node_id = payload["node_id"]
    event_type = payload["event_type"]
    timestamp = payload["timestamp"]

    # Build metadata from block-specific fields
    metadata = payload.get("metadata") or {}
    metadata["detection_rule"] = payload.get("detection_rule", "")
    metadata["block_ttl_seconds"] = payload.get("block_ttl_seconds", 0)
    # Pass through threat_tag for threat classification
    if payload.get("threat_tag"):
        metadata["threat_tag"] = payload["threat_tag"]

    # Enrich with geo data (country, ASN, organization)
    metadata = _enrich_metadata_with_geo(source_ip, metadata)

    # Extract request_count from metadata (default 1 if not provided)
    request_count = metadata.get("request_count", 1)
    if not isinstance(request_count, int) or request_count < 1:
        request_count = 1

    event_id = metadata.get("event_id", "") if isinstance(metadata, dict) else ""
    log_context = metadata.get("log_context") if isinstance(metadata, dict) else None

    record = upsert_ip_record(
        conn=db,
        ip_address=source_ip,
        node_id=node_id,
        event_type=event_type,
        timestamp=timestamp,
        is_block=True,
        metadata=metadata,
        request_count=request_count,
        event_id=event_id,
        log_context=log_context,
    )

    return {
        "status": "accepted",
        "ip_address": record["ip_address"],
        "total_times_seen": record["total_times_seen"],
        "total_times_blocked": record["total_times_blocked"],
    }


def process_batch(db, payload: dict) -> dict:
    """Validate and process a batch of events.

    Steps:
    1. Validate the batch envelope (events array present, size <= 500).
    2. Validate each event independently using validate_batch_event().
    3. Group valid events by source_ip.
    4. For each IP group, process events sequentially (each calls
       upsert_ip_record). Events for the same IP are processed in
       their original batch order.
    5. Assemble per-event results with status and any errors.

    Args:
        db: Database connection.
        payload: Batch request payload with an "events" list.

    Returns:
        A dict with keys: total_submitted, total_accepted,
        total_rejected, unique_ips_affected, results.

    Raises:
        ValidationError: If the batch envelope is invalid.
    """
    # Step 1: Validate envelope
    envelope_errors = validate_batch_request(payload)
    if envelope_errors:
        raise ValidationError(envelope_errors)

    events = payload["events"]
    total_submitted = len(events)
    results: list[dict] = []

    # Step 2: Validate each event independently
    # Track valid events with their original index for ordering
    valid_events: list[tuple[int, dict]] = []

    for idx, event in enumerate(events):
        event_errors = validate_batch_event(event)
        if event_errors:
            results.append(
                {
                    "index": idx,
                    "status": "rejected",
                    "errors": event_errors,
                }
            )
        else:
            results.append(
                {
                    "index": idx,
                    "status": "accepted",
                }
            )
            valid_events.append((idx, event))

    # Step 3: Group valid events by source_ip, preserving order
    ip_groups: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for idx, event in valid_events:
        ip_groups[event["source_ip"]].append((idx, event))

    # Step 4: Process each IP group atomically
    unique_ips_affected = set()
    for ip_address, group_events in ip_groups.items():
        try:
            for _idx, event in group_events:
                event_kind = event.get("event_kind", "sighting")
                is_block = event_kind == "block"

                # Build metadata
                metadata = event.get("metadata") or {}
                if "threat_tag" in event and event["threat_tag"] is not None:
                    metadata["threat_tag"] = event["threat_tag"]
                if is_block:
                    metadata["detection_rule"] = event.get("detection_rule", "")
                    metadata["block_ttl_seconds"] = event.get("block_ttl_seconds", 0)

                # Enrich with geo data (country, ASN, organization)
                metadata = _enrich_metadata_with_geo(event["source_ip"], metadata)

                # Extract request_count from metadata (default 1 if not provided)
                request_count = metadata.get("request_count", 1)
                if not isinstance(request_count, int) or request_count < 1:
                    request_count = 1

                event_id = event.get("event_id", "")
                log_context = metadata.get("log_context") if isinstance(metadata, dict) else None

                upsert_ip_record(
                    conn=db,
                    ip_address=event["source_ip"],
                    node_id=event["node_id"],
                    event_type=event["event_type"],
                    timestamp=event["timestamp"],
                    is_block=is_block,
                    metadata=metadata,
                    request_count=request_count,
                    event_id=event_id,
                    log_context=log_context,
                )

            unique_ips_affected.add(ip_address)
        except Exception as e:
            # If processing fails for an IP group, mark all events
            # in that group as rejected
            logger.error("Batch processing failed for IP %s: %s", ip_address, str(e))
            for idx, _event in group_events:
                # Find the result entry and update it
                for result in results:
                    if result["index"] == idx and result["status"] == "accepted":
                        result["status"] = "rejected"
                        result["errors"] = [f"processing error: {str(e)}"]
                        break

    # Step 5: Assemble summary
    total_accepted = sum(1 for r in results if r["status"] == "accepted")
    total_rejected = sum(1 for r in results if r["status"] == "rejected")

    return {
        "total_submitted": total_submitted,
        "total_accepted": total_accepted,
        "total_rejected": total_rejected,
        "unique_ips_affected": len(unique_ips_affected),
        "results": results,
    }


def query_ip_record(db, ip_address: str) -> dict | None:
    """Retrieve a single IP record with computed recency counters.

    Fetches the record from the database, computes rolling-window
    recency counters, and merges them into the record.

    Args:
        db: Database connection.
        ip_address: The IPv4 or IPv6 address to look up.

    Returns:
        A dict containing the full IP record with recency counters,
        or None if the IP address is not found.
    """
    record = get_ip_record(db, ip_address)
    if record is None:
        return None

    recency = compute_recency(db, ip_address)
    record.update(recency)

    try:
        record["reputation_score"] = compute_threat_score(record)
    except Exception:
        logger.error("Score computation failed for %s", ip_address, exc_info=True)
        record["reputation_score"] = None

    return record


def query_ip_records(
    db,
    filters: dict,
    page: int = 1,
    per_page: int = 50,
    sort_by: str = "last_seen_at",
    sort_order: str = "desc",
) -> dict:
    """Query IP records with filters, pagination, and sorting.

    Validates query parameters, calls search_ip_records, computes
    recency for each result, and returns a paginated response.

    Args:
        db: Database connection.
        filters: Dictionary of filter criteria (event_type, threat_tag,
            geo_country, repeat_offender, q).
        page: Page number (minimum 1).
        per_page: Results per page (min 1, max 200, default 50).
        sort_by: Column to sort by.
        sort_order: Sort direction ('asc' or 'desc').

    Returns:
        A dict with keys: records, total_count, current_page, total_pages.

    Raises:
        ValidationError: If query parameters are invalid.
    """
    # Validate query params
    query_params = dict(filters)
    if page is not None:
        query_params["page"] = page
    if per_page is not None:
        query_params["per_page"] = per_page

    errors = validate_query_params(query_params)
    if errors:
        raise ValidationError(errors)

    # Clamp pagination values
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 1
    elif per_page > 200:
        per_page = 200

    records, total_count = search_ip_records(
        conn=db,
        filters=filters,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    # Compute recency for each record
    for record in records:
        recency = compute_recency(db, record["ip_address"])
        record.update(recency)

        try:
            record["reputation_score"] = compute_threat_score(record)
        except Exception:
            logger.error("Score computation failed for %s", record.get("ip_address"), exc_info=True)
            record["reputation_score"] = None

    total_pages = math.ceil(total_count / per_page) if total_count > 0 else 0

    return {
        "records": records,
        "total_count": total_count,
        "current_page": page,
        "total_pages": total_pages,
    }

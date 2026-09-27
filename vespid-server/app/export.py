"""Data export helpers — CSV and JSON streaming responses.

Provides export_csv() and export_json() for generating downloadable
event data. Uses Transfer-Encoding: chunked for large datasets via
Flask streaming responses.

Requirements: 12.1, 12.2, 12.3, 12.4
"""

import csv
import io
import json

from flask import Response

# CSV column order with flattened geo_data fields
_CSV_COLUMNS = [
    "event_id",
    "node_id",
    "timestamp",
    "source_ip",
    "event_type",
    "action_taken",
    "country",
    "city",
    "asn",
    "org",
    "metadata",
]


def _flatten_event(event: dict) -> dict:
    """Flatten an event dict for CSV export.

    Extracts geo_data sub-fields (country, city, asn, org) into
    top-level columns and serialises metadata as a JSON string.

    Args:
        event: An event dict from the database (may have geo_data as
            a JSON string or dict, and metadata as a JSON string or dict).

    Returns:
        A flat dict suitable for CSV row writing.
    """
    # Parse geo_data if it's a JSON string
    geo_data = event.get("geo_data", {})
    if isinstance(geo_data, str):
        try:
            geo_data = json.loads(geo_data)
        except (json.JSONDecodeError, TypeError):
            geo_data = {}

    # Parse metadata if it's a JSON string
    metadata = event.get("metadata", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (json.JSONDecodeError, TypeError):
            metadata = {}

    return {
        "event_id": event.get("event_id", ""),
        "node_id": event.get("node_id", ""),
        "timestamp": event.get("timestamp", ""),
        "source_ip": event.get("source_ip", ""),
        "event_type": event.get("event_type", ""),
        "action_taken": event.get("action_taken", ""),
        "country": geo_data.get("country", event.get("geo_country", "")),
        "city": geo_data.get("city", event.get("geo_city", "")),
        "asn": geo_data.get("asn", event.get("geo_asn", "")),
        "org": geo_data.get("org", event.get("geo_org", "")),
        "metadata": json.dumps(metadata) if metadata else "{}",
    }


def export_csv(events: list[dict]) -> Response:
    """Generate a streaming CSV response with flattened geo_data columns.

    Columns: event_id, node_id, timestamp, source_ip, event_type,
    action_taken, country, city, asn, org, metadata

    Uses a generator to stream rows for Transfer-Encoding: chunked
    support with large datasets.

    Args:
        events: A list of event dicts from the database.

    Returns:
        A Flask Response with text/csv content type and a suggested
        filename for download.
    """

    def generate():
        # Write header row
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS)
        writer.writeheader()
        yield buf.getvalue()

        # Write data rows in chunks
        for event in events:
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS)
            flat = _flatten_event(event)
            writer.writerow(flat)
            yield buf.getvalue()

    return Response(
        generate(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=events.csv",
            "Transfer-Encoding": "chunked",
        },
    )


def export_json(events: list[dict]) -> Response:
    """Generate a JSON response containing an array of SecurityEvent objects.

    Each event includes its full geo_data and metadata as nested objects
    (parsed from JSON strings if necessary).

    Args:
        events: A list of event dicts from the database.

    Returns:
        A Flask Response with application/json content type and a
        suggested filename for download.
    """

    def _clean_event(event: dict) -> dict:
        """Ensure geo_data and metadata are dicts, not JSON strings."""
        result = dict(event)

        for field in ("geo_data", "metadata"):
            value = result.get(field, {})
            if isinstance(value, str):
                try:
                    result[field] = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    result[field] = {}

        return result

    def generate():
        yield "["
        for i, event in enumerate(events):
            cleaned = _clean_event(event)
            if i > 0:
                yield ","
            yield json.dumps(cleaned)
        yield "]"

    return Response(
        generate(),
        mimetype="application/json",
        headers={
            "Content-Disposition": "attachment; filename=events.json",
            "Transfer-Encoding": "chunked",
        },
    )

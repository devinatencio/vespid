"""Verification tests for Task 19.2: OBSERVED event threat_tag accumulation.

Validates Requirement 20, AC 2:
  WHEN an OBSERVED event carries a valid threat_tag, THE Intel_Database SHALL
  accumulate it into the ip_intel threat_tags array (with deduplication, same
  as block events).

These tests verify the end-to-end flow:
  process_sighting() → upsert_ip_record() → threat_tags array updated
"""

import json
import sqlite3

import pytest

from app.intel_models import init_intel_db
from app.intel_service import process_sighting


@pytest.fixture()
def intel_db(tmp_path):
    """Provide an in-memory SQLite DB with intel schema initialized."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_intel_db(conn, "sqlite")
    yield conn
    conn.close()


class TestSightingThreatTagAccumulation:
    """Verify that process_sighting() accumulates threat_tags with deduplication."""

    def test_sighting_with_explicit_threat_tag_accumulates(self, intel_db):
        """A sighting with an explicit threat_tag in metadata adds it to threat_tags array."""
        payload = {
            "source_ip": "10.0.0.1",
            "node_id": "node-001",
            "event_type": "LOG_MATCH",
            "timestamp": "2025-01-15T10:00:00",
            "metadata": {"threat_tag": "ssh-brute"},
        }
        result = process_sighting(intel_db, payload)
        assert result["status"] == "accepted"

        # Verify threat_tags array contains the tag
        row = intel_db.execute(
            "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
            ("10.0.0.1",),
        ).fetchone()
        tags = json.loads(row["threat_tags"])
        assert "ssh-brute" in tags

    def test_sighting_with_derived_threat_tag_accumulates(self, intel_db):
        """A sighting without explicit threat_tag derives it from event_type."""
        payload = {
            "source_ip": "10.0.0.2",
            "node_id": "node-001",
            "event_type": "SSH_BRUTE",
            "timestamp": "2025-01-15T10:00:00",
        }
        result = process_sighting(intel_db, payload)
        assert result["status"] == "accepted"

        # Derived tag should be event_type lowercased with _ replaced by -
        row = intel_db.execute(
            "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
            ("10.0.0.2",),
        ).fetchone()
        tags = json.loads(row["threat_tags"])
        assert "ssh-brute" in tags

    def test_sighting_threat_tag_deduplication(self, intel_db):
        """Duplicate threat_tags from multiple sightings are not added twice."""
        ip = "10.0.0.3"
        for i in range(3):
            payload = {
                "source_ip": ip,
                "node_id": f"node-{i:03d}",
                "event_type": "LOG_MATCH",
                "timestamp": f"2025-01-15T10:0{i}:00",
                "metadata": {"threat_tag": "ssh-brute"},
            }
            process_sighting(intel_db, payload)

        row = intel_db.execute(
            "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
            (ip,),
        ).fetchone()
        tags = json.loads(row["threat_tags"])
        # Should appear exactly once despite 3 sightings with same tag
        assert tags.count("ssh-brute") == 1

    def test_multiple_distinct_tags_accumulate(self, intel_db):
        """Multiple sightings with different threat_tags all accumulate."""
        ip = "10.0.0.4"
        tag_list = ["ssh-brute", "http-probe", "recon-correlation"]
        for i, tag in enumerate(tag_list):
            payload = {
                "source_ip": ip,
                "node_id": "node-001",
                "event_type": "LOG_MATCH",
                "timestamp": f"2025-01-15T10:0{i}:00",
                "metadata": {"threat_tag": tag},
            }
            process_sighting(intel_db, payload)

        row = intel_db.execute(
            "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
            (ip,),
        ).fetchone()
        tags = json.loads(row["threat_tags"])
        assert set(tags) == set(tag_list)
        assert len(tags) == 3

    def test_sighting_tags_combine_with_block_tags(self, intel_db):
        """Sighting threat_tags combine with block threat_tags in the same array."""
        from app.intel_service import process_block_event

        ip = "10.0.0.5"

        # First: a block event with tag "ssh-brute"
        block_payload = {
            "source_ip": ip,
            "node_id": "node-001",
            "event_type": "NFT_ACTION",
            "timestamp": "2025-01-15T10:00:00",
            "detection_rule": "ssh-brute",
            "block_ttl_seconds": 3600,
            "threat_tag": "ssh-brute",
        }
        process_block_event(intel_db, block_payload)

        # Then: a sighting with a different tag "http-probe"
        sighting_payload = {
            "source_ip": ip,
            "node_id": "node-002",
            "event_type": "LOG_MATCH",
            "timestamp": "2025-01-15T11:00:00",
            "metadata": {"threat_tag": "http-probe"},
        }
        process_sighting(intel_db, sighting_payload)

        row = intel_db.execute(
            "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
            (ip,),
        ).fetchone()
        tags = json.loads(row["threat_tags"])
        assert "ssh-brute" in tags
        assert "http-probe" in tags
        assert len(tags) == 2

    def test_sighting_same_tag_as_block_deduplicates(self, intel_db):
        """A sighting with the same tag as an existing block does not duplicate."""
        from app.intel_service import process_block_event

        ip = "10.0.0.6"

        # Block with tag "ssh-brute"
        block_payload = {
            "source_ip": ip,
            "node_id": "node-001",
            "event_type": "NFT_ACTION",
            "timestamp": "2025-01-15T10:00:00",
            "detection_rule": "ssh-brute",
            "block_ttl_seconds": 3600,
            "threat_tag": "ssh-brute",
        }
        process_block_event(intel_db, block_payload)

        # Sighting with same tag "ssh-brute"
        sighting_payload = {
            "source_ip": ip,
            "node_id": "node-002",
            "event_type": "LOG_MATCH",
            "timestamp": "2025-01-15T11:00:00",
            "metadata": {"threat_tag": "ssh-brute"},
        }
        process_sighting(intel_db, sighting_payload)

        row = intel_db.execute(
            "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
            (ip,),
        ).fetchone()
        tags = json.loads(row["threat_tags"])
        assert tags.count("ssh-brute") == 1
        assert len(tags) == 1

"""Tests for the admin Sigma sync route."""

from unittest.mock import MagicMock, patch


def test_sigma_sync_skips_user_modified_rules(admin_client, db):
    fake_run = MagicMock(returncode=0, stdout="sync ok", stderr="")

    with patch("subprocess.run", return_value=fake_run):
        first = admin_client.post("/api/v1/rules/sigma/sync")
        assert first.status_code == 200, first.get_data(as_text=True)
        first_body = first.get_json()
        assert first_body["ok"] is True
        assert first_body["inserted"] + first_body["updated"] > 0

        db.execute(
            "UPDATE detection_rules_custom SET regex = ?, user_modified = 1 WHERE name = ?",
            ("custom-regex", "sigma_exploit_framework_user_agent"),
        )
        db.commit()

        second = admin_client.post("/api/v1/rules/sigma/sync")
        assert second.status_code == 200, second.get_data(as_text=True)
        second_body = second.get_json()
        assert second_body["skipped_user_modified"] >= 1

    row = db.execute(
        "SELECT regex, user_modified FROM detection_rules_custom WHERE name = ?",
        ("sigma_exploit_framework_user_agent",),
    ).fetchone()
    assert row["regex"] == "custom-regex"
    assert int(row["user_modified"]) == 1


def test_sigma_sync_accepts_bearer_without_csrf(app, client, db, api_key):
    """The CLI uses Bearer auth; the sync view must be CSRF-exempt."""
    db.execute(
        "UPDATE api_keys SET role = 'admin' WHERE label = ?",
        ("test-api-key",),
    )
    db.commit()
    app.config["WTF_CSRF_ENABLED"] = True

    fake_run = MagicMock(returncode=0, stdout="sync ok", stderr="")
    with patch("subprocess.run", return_value=fake_run):
        response = client.post(
            "/api/v1/rules/sigma/sync",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
        )

    assert response.status_code == 200, response.get_data(as_text=True)
    assert response.get_json()["ok"] is True

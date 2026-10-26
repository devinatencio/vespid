"""Tests for the agent allowlist/blocklist sync endpoint."""

from app.models import add_ip_rule


def test_rules_lists_normalizes_bare_allowlist_ips(app, client, db, api_key):
    add_ip_rule(db, "allowlist", "72.201.135.201", "test", "admin")
    add_ip_rule(db, "allowlist", "10.0.0.0/24", "test", "admin")
    db.commit()

    response = client.get(
        "/api/v1/config/rules/lists",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        },
    )

    assert response.status_code == 200, response.get_data(as_text=True)
    body = response.get_json()
    assert "72.201.135.201/32" in body["allowlist"]
    assert "10.0.0.0/24" in body["allowlist"]
    assert "72.201.135.201" not in body["allowlist"]

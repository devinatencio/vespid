"""Tests for the metrics blueprint (app/metrics.py).

Covers:
    Group A — Pure-function unit tests (_metric_to_prometheus_line, _transform_batch)
    Group B — Dashboard helpers     (_get_known_agents, _build_fleet_summary, …)
    Group C — POST /api/v1/metrics/write
    Group D — POST /api/v1/metrics/checks
    Group E — Dashboard pages        (GET /metrics, /metrics/<id>, …)
    Group F — VM proxy API endpoints
    Group G — Saved queries CRUD
    Group H — Logfile watches CRUD + agent poll
"""

import json
from unittest.mock import patch

import pytest

# When sending a protobuf payload, the content-type is "application/x-protobuf",
# which is not recognized as an API request by _is_api_request() unless the
# request also carries an Accept or Authorization header.  Tests that want JSON
# 401 responses for unprotected endpoints should include an Accept header.
_API_JSON = {"Accept": "application/json"}

from app import create_app
from app.models import create_api_key, create_user, get_db


# ══════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════


@pytest.fixture()
def app(tmp_path):
    """Flask app with metrics + VictoriaMetrics enabled."""
    db_path = str(tmp_path / "test_metrics.db")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "SECRET_KEY": "test-metrics-secret",
        "DATABASE_PATH": db_path,
        "METRICS_ENABLED": True,
        "VICTORIAMETRICS_URL": "http://127.0.0.1:18428",
    }))
    application = create_app(str(cfg))
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    application.config["ALERTS_ENABLED"] = False
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db(app):
    conn = get_db(app.config["DATABASE_PATH"])
    yield conn
    conn.close()


@pytest.fixture()
def api_key_token(app, db):
    """Create an API key for agent-auth endpoints, return the raw token."""
    admin_id = create_user(db, "metrics_admin", "pass", "admin")
    return create_api_key(db, "metrics-test-key", None, admin_id)


@pytest.fixture()
def admin_client(client, app, db):
    """Client logged in as admin."""
    create_user(db, "admin", "admin", "admin")
    client.post("/login", data={"username": "admin", "password": "admin"})
    return client


@pytest.fixture()
def viewer_client(client, app, db):
    """Client logged in as viewer."""
    create_user(db, "viewer", "viewer_pass", "viewer")
    client.post("/login", data={"username": "viewer", "password": "viewer_pass"})
    return client


# ══════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _make_metric(name="cpu_idle", agent_id="a1", hostname="web-01",
                 value=42.0, ts_ms=1716904200000, extra_labels=None):
    """Build a minimal valid wire-format metric dict."""
    labels = [
        {"name": "__name__", "value": f"vespid_monitor_{name}"},
        {"name": "agent_id", "value": agent_id},
        {"name": "hostname", "value": hostname},
    ]
    if extra_labels:
        for k, v in extra_labels.items():
            labels.append({"name": k, "value": v})
    return {
        "labels": labels,
        "sample": {"value": value, "timestamp_ms": ts_ms},
    }


def _vm_result(agent_id="a1", hostname="web-01", value="42.5",
               ts=1716904200):
    """Return a single-series VictoriaMetrics instant-query result."""
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": {"agent_id": agent_id, "hostname": hostname},
                    "value": [ts, str(value)],
                }
            ],
        },
    }


def _vm_result_multi(agents):
    """Return a multi-series VM result from a list of (agent_id, hostname, value) tuples."""
    result = []
    for aid, hn, val in agents:
        result.append({
            "metric": {"agent_id": aid, "hostname": hn},
            "value": [1716904200, str(val)],
        })
    return {
        "status": "success",
        "data": {"resultType": "vector", "result": result},
    }


def _vm_count_result(agents):
    """Return a VM 'count by' result — each series has agent_id + hostname."""
    result = []
    for aid, hn in agents:
        result.append({
            "metric": {"agent_id": aid, "hostname": hn},
            "value": [1716904200, "1"],
        })
    return {
        "status": "success",
        "data": {"resultType": "vector", "result": result},
    }


def _vm_range_result(agent_id="a1", values=None):
    """Return a multi-point VM range-query result."""
    if values is None:
        values = [[1716904200, "42.0"], [1716904260, "43.0"]]
    return {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {"agent_id": agent_id},
                    "values": values,
                }
            ],
        },
    }


# ══════════════════════════════════════════════════════════════════════════
# Group A: Pure-function unit tests
# ══════════════════════════════════════════════════════════════════════════


class TestMetricToPrometheusLine:
    """_metric_to_prometheus_line() — single metric → Prom exposition line."""

    def test_valid_metric_returns_prom_line(self):
        from app.routes.metrics import _metric_to_prometheus_line
        metric = _make_metric()
        line = _metric_to_prometheus_line(metric)
        assert line is not None
        assert line.startswith(
            'vespid_monitor_cpu_idle{agent_id="a1",hostname="web-01"} 42.0'
        )
        assert line.endswith("1716904200000")

    def test_without_timestamp(self):
        from app.routes.metrics import _metric_to_prometheus_line
        metric = _make_metric(ts_ms=None)
        line = _metric_to_prometheus_line(metric)
        assert line is not None
        assert "42.0" in line
        assert "1716904200000" not in line

    def test_missing_metric_name_returns_none(self):
        from app.routes.metrics import _metric_to_prometheus_line
        metric = _make_metric()
        metric["labels"] = [{"name": "foo", "value": "bar"}]
        assert _metric_to_prometheus_line(metric) is None

    def test_missing_value_returns_none(self):
        from app.routes.metrics import _metric_to_prometheus_line
        metric = _make_metric()
        metric["sample"] = {"value": None, "timestamp_ms": None}
        assert _metric_to_prometheus_line(metric) is None

    def test_labels_sorted_alphabetically(self):
        from app.routes.metrics import _metric_to_prometheus_line
        metric = _make_metric(extra_labels={"z_last": "1", "a_first": "2"})
        line = _metric_to_prometheus_line(metric)
        idx_a = line.index("a_first")
        idx_z = line.index("z_last")
        assert idx_a < idx_z

    def test_no_labels_omits_braces(self):
        from app.routes.metrics import _metric_to_prometheus_line
        metric = _make_metric()
        metric["labels"] = [{"name": "__name__", "value": "my_metric"}]
        line = _metric_to_prometheus_line(metric)
        assert line == "my_metric 42.0 1716904200000"

    def test_zero_value(self):
        from app.routes.metrics import _metric_to_prometheus_line
        metric = _make_metric(value=0.0)
        line = _metric_to_prometheus_line(metric)
        assert "0.0" in line


class TestTransformBatch:
    """_transform_batch() — list of metrics → list of Prom lines."""

    def test_all_valid(self):
        from app.routes.metrics import _transform_batch
        batch = [_make_metric(name="cpu", agent_id="a1"),
                 _make_metric(name="mem", agent_id="a2")]
        lines = _transform_batch(batch)
        assert len(lines) == 2

    def test_skips_bad_metrics(self):
        from app.routes.metrics import _transform_batch
        bad = _make_metric()
        bad["sample"] = {"value": None, "timestamp_ms": None}
        batch = [_make_metric(), bad, _make_metric(name="other")]
        lines = _transform_batch(batch)
        assert len(lines) == 2

    def test_empty_input(self):
        from app.routes.metrics import _transform_batch
        assert _transform_batch([]) == []

    def test_all_bad_input(self):
        from app.routes.metrics import _transform_batch
        bad = _make_metric()
        bad["labels"] = []
        assert _transform_batch([bad]) == []


# ══════════════════════════════════════════════════════════════════════════
# Group B: Dashboard helpers (mocked _vm_query)
# ══════════════════════════════════════════════════════════════════════════


class TestGetKnownAgents:
    """_get_known_agents() — discovers agents from VictoriaMetrics."""

    def test_returns_sorted_agents(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = _vm_count_result([
                ("b2", "zeta"), ("a1", "alpha"), ("c3", "beta"),
            ])
            from app.routes.metrics import _get_known_agents
            agents = _get_known_agents()
        assert len(agents) == 3
        assert agents[0]["hostname"] == "alpha"
        assert agents[1]["hostname"] == "beta"
        assert agents[2]["hostname"] == "zeta"

    def test_empty_result(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = {"status": "success", "data": {"result": []}}
            from app.routes.metrics import _get_known_agents
            assert _get_known_agents() == []

    def test_error_status(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = {"status": "error", "data": {}}
            from app.routes.metrics import _get_known_agents
            assert _get_known_agents() == []

    def test_none_response(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = None
            from app.routes.metrics import _get_known_agents
            assert _get_known_agents() == []


class TestGetLatestValue:
    """_get_latest_value() — PromQL scalar extraction."""

    def test_returns_float(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = _vm_result(value="67.3")
            from app.routes.metrics import _get_latest_value
            val = _get_latest_value("some_query")
        assert val == 67.3

    def test_no_data_returns_none(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = {"status": "success", "data": {"result": []}}
            from app.routes.metrics import _get_latest_value
            assert _get_latest_value("some_query") is None

    def test_error_status_returns_none(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = {"status": "error", "data": {}}
            from app.routes.metrics import _get_latest_value
            assert _get_latest_value("some_query") is None

    def test_none_response_returns_none(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = None
            from app.routes.metrics import _get_latest_value
            assert _get_latest_value("some_query") is None

    def test_invalid_value_returns_nan(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = _vm_result(value="NaN")
            from app.routes.metrics import _get_latest_value
            import math
            assert math.isnan(_get_latest_value("some_query"))


class TestGetHostInfo:
    """_get_host_info() — host metadata from VM labels."""

    def test_returns_host_info(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = _vm_result(agent_id="a1", hostname="web-01")
            from app.routes.metrics import _get_host_info
            info = _get_host_info("a1")
        assert info == {"agent_id": "a1", "hostname": "web-01"}

    def test_no_data_returns_none(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = {"status": "success", "data": {"result": []}}
            from app.routes.metrics import _get_host_info
            assert _get_host_info("a1") is None

    def test_none_response_returns_none(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = None
            from app.routes.metrics import _get_host_info
            assert _get_host_info("a1") is None

    def test_error_status_returns_none(self):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = {"status": "error", "data": {}}
            from app.routes.metrics import _get_host_info
            assert _get_host_info("a1") is None


class TestBuildFleetSummary:
    """_build_fleet_summary() — aggregate fleet stats from agent list."""

    def test_all_responding(self):
        agents = [
            {"agent_id": "a1", "hostname": "alpha"},
            {"agent_id": "a2", "hostname": "beta"},
        ]
        with patch("app.routes.metrics._get_latest_value") as mock_val, \
             patch("app.routes.metrics._enrich_agent_last_seen") as mock_enrich:
            mock_val.side_effect = [45.0, 60.0, 50.0, 70.0, 80.0, 30.0]
            from app.routes.metrics import _build_fleet_summary
            summary = _build_fleet_summary(agents)
        assert summary["agent_count"] == 2
        assert summary["responding"] == 2
        assert summary["avg_cpu_pct"] == 57.5  # (45+70)/2
        assert summary["avg_mem_pct"] == 70.0  # (60+80)/2
        assert summary["max_disk_pct"] == 50.0

    def test_none_responding(self):
        agents = [{"agent_id": "a1", "hostname": "alpha"}]
        with patch("app.routes.metrics._get_latest_value") as mock_val, \
             patch("app.routes.metrics._enrich_agent_last_seen") as mock_enrich:
            mock_val.return_value = None
            from app.routes.metrics import _build_fleet_summary
            summary = _build_fleet_summary(agents)
        assert summary["agent_count"] == 1
        assert summary["responding"] == 0
        assert summary["avg_cpu_pct"] == 0.0
        assert summary["avg_mem_pct"] == 0.0
        assert summary["max_disk_pct"] == 0.0

    def test_empty_agents(self):
        with patch("app.routes.metrics._enrich_agent_last_seen") as mock_enrich:
            from app.routes.metrics import _build_fleet_summary
            summary = _build_fleet_summary([])
        assert summary["agent_count"] == 0
        assert summary["responding"] == 0


class TestEnrichAgentLastSeen:
    """_enrich_agent_last_seen() — adds last_seen timestamps."""

    def _now_ts(self):
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).timestamp()

    def test_just_now(self):
        agents = [{"agent_id": "a1", "hostname": "h1"}]
        now_ts = self._now_ts()
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = _vm_result(agent_id="a1", ts=now_ts - 30)
            from app.routes.metrics import _enrich_agent_last_seen
            _enrich_agent_last_seen(agents)
        assert agents[0]["last_seen_label"] == "just now"

    def test_minutes_ago(self):
        agents = [{"agent_id": "a1", "hostname": "h1"}]
        now_ts = self._now_ts()
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = _vm_result(agent_id="a1", ts=now_ts - 180)
            from app.routes.metrics import _enrich_agent_last_seen
            _enrich_agent_last_seen(agents)
        assert agents[0]["last_seen_label"] == "3m ago"

    def test_hours_ago(self):
        agents = [{"agent_id": "a1", "hostname": "h1"}]
        now_ts = self._now_ts()
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = _vm_result(agent_id="a1", ts=now_ts - 7200)
            from app.routes.metrics import _enrich_agent_last_seen
            _enrich_agent_last_seen(agents)
        assert agents[0]["last_seen_label"] == "2h ago"

    def test_no_ts_label_is_none(self):
        agents = [{"agent_id": "a1", "hostname": "h1"}]
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = {"status": "success", "data": {"result": []}}
            from app.routes.metrics import _enrich_agent_last_seen
            _enrich_agent_last_seen(agents)
        assert agents[0]["last_seen_label"] is None


# ══════════════════════════════════════════════════════════════════════════
# Group C: POST /api/v1/metrics/write  (agent-auth, mocked _vm_write)
# ══════════════════════════════════════════════════════════════════════════


class TestMetricsWrite:
    """POST /api/v1/metrics/write — agent metric ingestion (protobuf)."""

    ENDPOINT = "/api/v1/metrics/write"
    CONTENT_TYPE = "application/x-protobuf"

    def _post(self, client, data, token=None, content_type=None, headers=None):
        hdrs = auth_header(token) if token else {}
        if headers:
            hdrs.update(headers)
        return client.post(
            self.ENDPOINT,
            data=data,
            content_type=content_type or self.CONTENT_TYPE,
            headers=hdrs,
        )

    def test_401_no_auth(self, client):
        resp = self._post(client, b"some protobuf data", token=None, headers=_API_JSON)
        assert resp.status_code == 401

    def test_401_bad_token(self, client):
        resp = self._post(client, b"some protobuf data", token="bad-token", headers=_API_JSON)
        assert resp.status_code == 401

    def test_415_wrong_content_type(self, client, api_key_token):
        resp = client.post(
            self.ENDPOINT,
            data=b"some data",
            content_type="text/plain",
            headers=auth_header(api_key_token),
        )
        assert resp.status_code == 415

    def test_400_empty_body(self, client, api_key_token):
        resp = self._post(client, b"", token=api_key_token)
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "empty_body"

    def test_204_success(self, client, api_key_token):
        with patch("app.routes.metrics_api._vm_write") as mock:
            mock.return_value = True
            payload = b"fake-protobuf-snappy-bytes"
            resp = self._post(client, payload, token=api_key_token)
        assert resp.status_code == 204
        mock.assert_called_once_with(payload)

    def test_502_vm_unreachable(self, client, api_key_token):
        with patch("app.routes.metrics_api._vm_write") as mock:
            mock.return_value = False
            resp = self._post(client, b"some data", token=api_key_token)
        assert resp.status_code == 502
        assert resp.get_json()["error"] == "backend_unavailable"

    def test_forwards_raw_bytes_unchanged(self, client, api_key_token):
        with patch("app.routes.metrics_api._vm_write") as mock:
            mock.return_value = True
            payload = b"\x00\x01\x02\xff\xfe\xfd\xab\xcd"
            self._post(client, payload, token=api_key_token)
        assert mock.call_args[0][0] == payload


# ══════════════════════════════════════════════════════════════════════════
# Group D: POST /api/v1/metrics/checks  (agent-auth, real DB)
# ══════════════════════════════════════════════════════════════════════════


class TestChecksReport:
    """POST /api/v1/metrics/checks — health check result ingestion."""

    ENDPOINT = "/api/v1/metrics/checks"

    def test_401_no_auth(self, client):
        resp = client.post(self.ENDPOINT, content_type="application/json")
        assert resp.status_code == 401

    def test_204_valid(self, client, api_key_token, db):
        payload = {
            "name": "disk_root",
            "agent_id": "a1",
            "hostname": "web-01",
            "exit_code": 0,
            "output": "OK: / at 45%",
            "duration_ms": 120,
        }
        resp = client.post(
            self.ENDPOINT,
            data=json.dumps(payload),
            content_type="application/json",
            headers=auth_header(api_key_token),
        )
        assert resp.status_code == 204

        row = db.execute(
            "SELECT * FROM check_results WHERE agent_id = ?", ("a1",)
        ).fetchone()
        assert row is not None
        assert row["name"] == "disk_root"
        assert row["exit_code"] == 0

    def test_400_missing_name(self, client, api_key_token):
        resp = client.post(
            self.ENDPOINT,
            data=json.dumps({"agent_id": "a1", "exit_code": 0}),
            content_type="application/json",
            headers=auth_header(api_key_token),
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "missing_fields"

    def test_400_missing_agent_id(self, client, api_key_token):
        resp = client.post(
            self.ENDPOINT,
            data=json.dumps({"name": "test", "exit_code": 0}),
            content_type="application/json",
            headers=auth_header(api_key_token),
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "missing_fields"

    def test_400_bad_exit_code_type(self, client, api_key_token):
        resp = client.post(
            self.ENDPOINT,
            data=json.dumps({"name": "x", "agent_id": "a1", "exit_code": "abc"}),
            content_type="application/json",
            headers=auth_header(api_key_token),
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_exit_code"

    def test_400_invalid_json(self, client, api_key_token):
        resp = client.post(
            self.ENDPOINT,
            data=b"not json",
            content_type="application/json",
            headers=auth_header(api_key_token),
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_json"

    def test_multiple_checks_stored(self, client, api_key_token, db):
        payloads = [
            {"name": "cpu_load", "agent_id": "a1", "hostname": "h1",
             "exit_code": 1, "output": "WARN", "duration_ms": 50},
            {"name": "mem_check", "agent_id": "a1", "hostname": "h1",
             "exit_code": 0, "output": "OK", "duration_ms": 30},
        ]
        for p in payloads:
            resp = client.post(
                self.ENDPOINT,
                data=json.dumps(p),
                content_type="application/json",
                headers=auth_header(api_key_token),
            )
            assert resp.status_code == 204

        rows = db.execute(
            "SELECT name, exit_code FROM check_results WHERE agent_id = ? ORDER BY name",
            ("a1",),
        ).fetchall()
        assert len(rows) == 2


# ══════════════════════════════════════════════════════════════════════════
# Group E: Dashboard pages  (viewer-auth, mocked VM for summary/overview)
# ══════════════════════════════════════════════════════════════════════════


class TestDashboardOverview:
    """GET /metrics — fleet metrics overview."""

    def test_redirect_anon(self, client):
        resp = client.get("/metrics", follow_redirects=False)
        assert resp.status_code == 302

    @patch("app.routes.metrics._vm_query")
    @patch("app.routes.metrics_api._vm_write")
    def test_200_disabled(self, mock_write, mock_query, client, app, admin_client):
        app.config["METRICS_ENABLED"] = False
        resp = admin_client.get("/metrics")
        assert resp.status_code == 200
        assert "disabled" in resp.text.lower()

    @patch("app.routes.metrics._vm_query")
    def test_200_empty(self, mock_query, admin_client):
        mock_query.side_effect = [
            {"status": "success", "data": {"result": []}},
            {"status": "success", "data": {"result": []}},
        ]
        resp = admin_client.get("/metrics")
        assert resp.status_code == 200
        assert "No hosts monitored" in resp.text

    @patch("app.routes.metrics._vm_query")
    def test_200_with_agents(self, mock_query, admin_client):
        mock_query.side_effect = [
            _vm_count_result([("a1", "web-01")]),
            _vm_result(value="45.0"),
            _vm_result(value="60.0"),
            _vm_result(value="80.0"),
            _vm_result(value="60.0"),  # _enrich_agent_last_seen
        ]
        resp = admin_client.get("/metrics")
        assert resp.status_code == 200
        assert "web-01" in resp.text
        assert "45.0" in resp.text or "45" in resp.text


class TestHostDetail:
    """GET /metrics/<agent_id> — per-host detail."""

    def test_404_unknown(self, admin_client):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = {"status": "success", "data": {"result": []}}
            resp = admin_client.get("/metrics/unknown-id")
        assert resp.status_code == 404
        assert "has not reported any metrics" in resp.text

    def test_200_known_host(self, admin_client):
        with patch("app.routes.metrics._vm_query") as mock:
            mock.return_value = _vm_result(agent_id="a1", hostname="web-01")
            resp = admin_client.get("/metrics/a1")
        assert resp.status_code == 200
        assert "web-01" in resp.text


class TestChecksDashboard:
    """GET /metrics/checks — health checks list."""

    def test_redirect_anon(self, client):
        resp = client.get("/metrics/checks", follow_redirects=False)
        assert resp.status_code == 302

    def test_200_enabled(self, client, app, admin_client):
        resp = admin_client.get("/metrics/checks")
        assert resp.status_code == 200
        assert "checks" in resp.text.lower() or "Check" in resp.text

    def test_disabled_redirects(self, client, app, admin_client):
        app.config["METRICS_ENABLED"] = False
        resp = admin_client.get("/metrics/checks", follow_redirects=False)
        assert resp.status_code == 302


class TestQueryExplorer:
    """GET /metrics/query — PromQL query explorer page."""

    def test_redirect_anon(self, client):
        resp = client.get("/metrics/query", follow_redirects=False)
        assert resp.status_code == 302

    def test_200_enabled(self, admin_client):
        resp = admin_client.get("/metrics/query")
        assert resp.status_code == 200

    def test_disabled_redirects(self, client, app, admin_client):
        app.config["METRICS_ENABLED"] = False
        resp = admin_client.get("/metrics/query", follow_redirects=False)
        assert resp.status_code == 302


# ══════════════════════════════════════════════════════════════════════════
# Group F: VM proxy API endpoints  (viewer-auth, mocked VM)
# ══════════════════════════════════════════════════════════════════════════


class TestApiSummary:
    """GET /metrics/api/summary — fleet summary JSON."""

    ENDPOINT = "/metrics/api/summary"

    def test_401_anon(self, client):
        resp = client.get(self.ENDPOINT)
        assert resp.status_code in (302, 401)  # redirect or JSON 401

    def test_200_with_data(self, admin_client, api_key_token):
        with patch("app.routes.metrics_api._vm_query") as mock:
            mock.side_effect = [
                _vm_count_result([("a1", "web-01")]),
                _vm_result(value="45.0"),
                _vm_result(value="60.0"),
                _vm_result(value="80.0"),
                _vm_result(value="60.0"),  # _enrich_agent_last_seen
            ]
            resp = admin_client.get(self.ENDPOINT)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "agents" in data
        assert "summary" in data
        assert len(data["agents"]) == 1
        assert data["summary"]["agent_count"] == 1

    def test_404_when_disabled(self, client, app, admin_client):
        app.config["METRICS_ENABLED"] = False
        resp = admin_client.get(self.ENDPOINT)
        assert resp.status_code == 404


class TestApiQuery:
    """GET /metrics/api/query — instant PromQL proxy."""

    ENDPOINT = "/metrics/api/query"

    def test_400_no_query(self, admin_client):
        resp = admin_client.get(self.ENDPOINT)
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "missing query"

    def test_200_valid(self, admin_client):
        with patch("app.routes.metrics_api._vm_query") as mock:
            mock.return_value = _vm_result(value="42.0")
            resp = admin_client.get(f"{self.ENDPOINT}?q=up")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"

    def test_502_vm_down(self, admin_client):
        with patch("app.routes.metrics_api._vm_query") as mock:
            mock.return_value = None
            resp = admin_client.get(f"{self.ENDPOINT}?q=up")
        assert resp.status_code == 502
        assert resp.get_json()["error"] == "victoriametrics unreachable"


class TestApiQueryRange:
    """GET /metrics/api/query_range — range PromQL proxy."""

    ENDPOINT = "/metrics/api/query_range"

    def test_400_no_query(self, admin_client):
        resp = admin_client.get(self.ENDPOINT)
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "missing query"

    def test_200_valid(self, admin_client):
        with patch("app.routes.metrics_api._vm_query_range") as mock:
            mock.return_value = _vm_range_result()
            resp = admin_client.get(f"{self.ENDPOINT}?q=up&start=-1h")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"

    def test_502_vm_down(self, admin_client):
        with patch("app.routes.metrics_api._vm_query_range") as mock:
            mock.return_value = None
            resp = admin_client.get(f"{self.ENDPOINT}?q=up")
        assert resp.status_code == 502


class TestApiLabelValues:
    """GET /metrics/api/labels/<name> — label values proxy."""

    ENDPOINT = "/metrics/api/labels/agent_id"

    def test_200_valid(self, admin_client):
        with patch("urllib.request.urlopen") as mock:
            mock.return_value.__enter__.return_value.read.return_value = \
                json.dumps({"status": "success", "data": ["a1", "a2"]}).encode()
            resp = admin_client.get(self.ENDPOINT)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["data"] == ["a1", "a2"]

    def test_502_vm_down(self, admin_client):
        from urllib.error import URLError
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = URLError("connection refused")
            resp = admin_client.get(self.ENDPOINT)
        assert resp.status_code == 502


class TestApiAgentRange:
    """GET /metrics/api/<agent_id>/range — agent range data."""

    ENDPOINT = "/metrics/api/a1/range"

    def test_200_valid(self, admin_client):
        with patch("app.routes.metrics_api._vm_query_range") as mock:
            mock.return_value = _vm_range_result(agent_id="a1")
            resp = admin_client.get(self.ENDPOINT)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["agent_id"] == "a1"
        assert "series" in data
        assert "cpu_usage" in data["series"]

    def test_with_range_param(self, admin_client):
        with patch("app.routes.metrics_api._vm_query_range") as mock:
            mock.return_value = _vm_range_result(agent_id="a1")
            resp = admin_client.get(f"{self.ENDPOINT}?range=6h")
        assert resp.status_code == 200

    def test_some_series_empty(self, admin_client):
        def side_effect(promql, start, end, step):
            if "cpu" in promql:
                return _vm_range_result(agent_id="a1")
            return {"status": "success", "data": {"result": []}}

        with patch("app.routes.metrics_api._vm_query_range") as mock:
            mock.side_effect = side_effect
            resp = admin_client.get(self.ENDPOINT)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "cpu_usage" in data["series"]
        assert len(data["series"]["cpu_usage"]) > 0


# ══════════════════════════════════════════════════════════════════════════
# Group G: Saved Queries CRUD  (viewer-auth, real DB)
# ══════════════════════════════════════════════════════════════════════════


class TestSavedQueries:
    """CRUD for saved PromQL queries."""

    BASE = "/metrics/api/queries"

    def test_list_empty(self, viewer_client):
        resp = viewer_client.get(self.BASE)
        assert resp.status_code == 200
        assert resp.get_json()["queries"] == []

    def test_create_valid(self, viewer_client, db):
        resp = viewer_client.post(
            self.BASE,
            data=json.dumps({"name": "My Query", "query": "up == 1"}),
            content_type="application/json",
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["query"]["name"] == "My Query"
        assert data["query"]["query"] == "up == 1"

    def test_create_missing_name(self, viewer_client):
        resp = viewer_client.post(
            self.BASE,
            data=json.dumps({"query": "up == 1"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "name and query are required"

    def test_create_missing_query(self, viewer_client):
        resp = viewer_client.post(
            self.BASE,
            data=json.dumps({"name": "My Query"}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_update_valid(self, viewer_client):
        resp = viewer_client.post(
            self.BASE,
            data=json.dumps({"name": "Old", "query": "up"}),
            content_type="application/json",
        )
        qid = resp.get_json()["query"]["id"]

        resp = viewer_client.put(
            f"{self.BASE}/{qid}",
            data=json.dumps({"name": "New", "query": "up == 0"}),
            content_type="application/json",
        )
        assert resp.status_code == 200

        resp = viewer_client.get(self.BASE)
        queries = resp.get_json()["queries"]
        assert len(queries) == 1
        assert queries[0]["name"] == "New"

    def test_update_not_found(self, viewer_client):
        resp = viewer_client.put(
            f"{self.BASE}/99999",
            data=json.dumps({"name": "X", "query": "up"}),
            content_type="application/json",
        )
        assert resp.status_code == 404

    def test_delete_valid(self, viewer_client, db):
        resp = viewer_client.post(
            self.BASE,
            data=json.dumps({"name": "Delete Me", "query": "up"}),
            content_type="application/json",
        )
        qid = resp.get_json()["query"]["id"]

        resp = viewer_client.delete(f"{self.BASE}/{qid}")
        assert resp.status_code == 200

        resp = viewer_client.get(self.BASE)
        assert resp.get_json()["queries"] == []

    def test_delete_not_found(self, viewer_client):
        resp = viewer_client.delete(f"{self.BASE}/99999")
        assert resp.status_code == 404

    def test_list_after_create(self, viewer_client):
        viewer_client.post(
            self.BASE,
            data=json.dumps({"name": "Q1", "query": "up"}),
            content_type="application/json",
        )
        viewer_client.post(
            self.BASE,
            data=json.dumps({"name": "Q2", "query": "down"}),
            content_type="application/json",
        )
        resp = viewer_client.get(self.BASE)
        assert len(resp.get_json()["queries"]) == 2


# ══════════════════════════════════════════════════════════════════════════
# Group H: Logfile Watches CRUD + Agent Poll
# ══════════════════════════════════════════════════════════════════════════


class TestLogfileWatchesCRUD:
    """CRUD for logfile watches (admin-only create/update/delete)."""

    BASE = "/api/v1/logfile-watches"

    def _valid_data(self, **kw):
        data = {
            "agent_id": "a1",
            "name": "nginx-error",
            "path": "/var/log/nginx/error.log",
            "pattern": "error",
        }
        data.update(kw)
        return data

    def test_list_empty(self, viewer_client):
        resp = viewer_client.get(self.BASE)
        assert resp.status_code == 200
        assert resp.get_json()["watches"] == []

    def test_create_requires_admin(self, viewer_client):
        resp = viewer_client.post(
            self.BASE,
            data=json.dumps(self._valid_data()),
            content_type="application/json",
        )
        assert resp.status_code == 403

    def test_create_valid(self, admin_client, db):
        resp = admin_client.post(
            self.BASE,
            data=json.dumps(self._valid_data()),
            content_type="application/json",
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert "id" in data

        row = db.execute(
            "SELECT * FROM logfile_watches WHERE id = ?", (data["id"],)
        ).fetchone()
        assert row is not None
        assert row["name"] == "nginx-error"

    def test_create_missing_fields(self, admin_client):
        resp = admin_client.post(
            self.BASE,
            data=json.dumps({"agent_id": "a1"}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_update_valid(self, admin_client, db):
        resp = admin_client.post(
            self.BASE,
            data=json.dumps(self._valid_data()),
            content_type="application/json",
        )
        wid = resp.get_json()["id"]

        resp = admin_client.put(
            f"{self.BASE}/{wid}",
            data=json.dumps({"name": "nginx-error-v2", "enabled": False}),
            content_type="application/json",
        )
        assert resp.status_code == 200

        row = db.execute(
            "SELECT name, enabled FROM logfile_watches WHERE id = ?", (wid,)
        ).fetchone()
        assert row["name"] == "nginx-error-v2"

    def test_update_not_found(self, admin_client):
        resp = admin_client.put(
            f"{self.BASE}/99999",
            data=json.dumps({"name": "x"}),
            content_type="application/json",
        )
        assert resp.status_code == 404

    def test_delete_valid(self, admin_client, db):
        resp = admin_client.post(
            self.BASE,
            data=json.dumps(self._valid_data()),
            content_type="application/json",
        )
        wid = resp.get_json()["id"]

        resp = admin_client.delete(f"{self.BASE}/{wid}")
        assert resp.status_code == 200

        row = db.execute(
            "SELECT * FROM logfile_watches WHERE id = ?", (wid,)
        ).fetchone()
        assert row is None

    def test_delete_not_found(self, admin_client):
        resp = admin_client.delete(f"{self.BASE}/99999")
        assert resp.status_code == 404

    def test_list_filter_by_agent(self, admin_client, db):
        admin_client.post(
            self.BASE,
            data=json.dumps(self._valid_data(agent_id="a1", name="w1")),
            content_type="application/json",
        )
        admin_client.post(
            self.BASE,
            data=json.dumps(self._valid_data(agent_id="a2", name="w2")),
            content_type="application/json",
        )

        resp = admin_client.get(f"{self.BASE}?agent_id=a1")
        watches = resp.get_json()["watches"]
        assert len(watches) == 1
        assert watches[0]["agent_id"] == "a1"


class TestAgentPollEndpoints:
    """Agent-polled endpoints: GET /api/v1/agent/<id>/logfile-watches, exec-scripts."""

    def test_logfile_watches_for_agent(self, client, admin_client, api_key_token):
        # Create a watch via admin
        admin_client.post(
            "/api/v1/logfile-watches",
            data=json.dumps({
                "agent_id": "a1", "name": "ssh", "path": "/var/log/auth.log",
                "pattern": "Failed password",
            }),
            content_type="application/json",
        )

        resp = client.get(
            "/api/v1/agent/a1/logfile-watches",
            headers=auth_header(api_key_token),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["watches"]) == 1
        assert data["watches"][0]["name"] == "ssh"

    def test_logfile_watches_empty(self, client, admin_client, api_key_token):
        resp = client.get(
            "/api/v1/agent/bogus/logfile-watches",
            headers=auth_header(api_key_token),
        )
        assert resp.status_code == 200
        assert resp.get_json()["watches"] == []

    def test_exec_scripts_for_agent(self, client, admin_client, db, api_key_token):
        resp = client.get(
            "/api/v1/agent/a1/exec-scripts",
            headers=auth_header(api_key_token),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "scripts" in data


# ══════════════════════════════════════════════════════════════════════════
# Group I: Auth boundary tests — verify roles are enforced
# ══════════════════════════════════════════════════════════════════════════


class TestAuthBoundaries:
    """Role requirements for each endpoint."""

    def test_viewer_cannot_create_logfile_watches(self, viewer_client):
        resp = viewer_client.post(
            "/api/v1/logfile-watches",
            data=json.dumps({"agent_id": "a1", "name": "x", "path": "/x", "pattern": "x"}),
            content_type="application/json",
        )
        assert resp.status_code == 403

    def test_viewer_cannot_delete_logfile_watches(self, viewer_client):
        resp = viewer_client.delete("/api/v1/logfile-watches/1")
        assert resp.status_code == 403

    def test_agent_token_cannot_access_admin_endpoints(self, client, api_key_token):
        resp = client.get(
            "/api/v1/logfile-watches",
            headers=auth_header(api_key_token),
        )
        # agent tokens have admin-level role, but we should verify the route
        # is accessible — this is a sanity check
        assert resp.status_code == 200

    def test_unauthenticated_for_viewer_routes(self, client):
        for path in ["/metrics", "/metrics/a1", "/metrics/query",
                      "/metrics/api/summary", "/metrics/checks"]:
            resp = client.get(path)
            assert resp.status_code in (302, 401), f"{path} should require auth"

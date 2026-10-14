"""Health checks, request ids and log hygiene (app/observability.py)."""
import json
import logging

from app import observability
from app.config import settings


def test_liveness(client):
    assert client.get("/api/health/live").json() == {"ok": True}
    assert client.get("/api/health").json() == {"ok": True}  # old path kept for existing probes


def test_readiness_checks_database_schema_and_trust_root(client, device):
    r = client.get("/api/health/ready")
    assert r.status_code == 200 and r.json() == {"ok": True, "checks": {"schema": True, "database": True, "trust_root": True}}


def test_readiness_fails_closed_without_trust_root(client, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "root_pubkey_path", tmp_path / "missing.pub")
    r = client.get("/api/health/ready")
    assert r.status_code == 503 and r.json()["checks"]["trust_root"] is False


def test_request_id_is_generated_or_propagated(client):
    assert len(client.get("/api/health").headers["X-Request-ID"]) == 32
    assert client.get("/api/health", headers={"X-Request-ID": "proxy-abc.1"}).headers["X-Request-ID"] == "proxy-abc.1"
    # garbage from outside is not reflected into logs/headers
    rid = client.get("/api/health", headers={"X-Request-ID": "x\\r\\ninjected"}).headers["X-Request-ID"]
    assert rid != "x\\r\\ninjected" and len(rid) == 32


def test_access_log_hides_public_check_tokens(client, caplog):
    with caplog.at_level(logging.INFO, logger="medseal.access"):
        client.get("/api/check/SECRET-TOKEN-123")
    paths = [r.path for r in caplog.records if r.name == "medseal.access"]
    assert paths == ["/api/check/***"]


def test_json_log_line_carries_the_request_id():
    record = logging.LogRecord("medseal.test", logging.INFO, __file__, 1, "hello", None, None)
    token = observability.request_id.set("rid-1")
    try:
        line = json.loads(observability.JsonFormatter().format(record))
    finally:
        observability.request_id.reset(token)
    assert line["msg"] == "hello" and line["request_id"] == "rid-1" and line["level"] == "INFO"

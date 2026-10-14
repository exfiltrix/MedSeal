"""The audit log is hash-chained (app/audit.py): edits and deletions show up in GET /audit/check."""
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import delete, select, update

from app import audit, db
from app.models import AuditEvent
from tests.conftest import admin_headers, xray_png


def _check(client):
    r = client.get("/api/audit/check", headers=admin_headers())
    assert r.status_code == 200, r.text
    return r.json()


def _seal(client, device, seed):
    r = client.post("/api/seal", files={"file": ("x.png", xray_png(seed=seed))}, headers=device["auth"])
    assert r.status_code == 200, r.text


def test_rows_are_linked_right_after_commit(client, device):
    for seed in range(3):
        _seal(client, device, 400 + seed)
    with db.SessionLocal() as s:
        rows = s.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    assert rows and all(r.entry_hash for r in rows)  # linked without anyone calling /check
    assert rows[0].prev_hash == audit.GENESIS
    assert all(b.prev_hash == a.entry_hash for a, b in zip(rows, rows[1:]))
    assert _check(client)["ok"] is True


def test_editing_an_audit_row_is_detected(client, device):
    _seal(client, device, 410)
    _seal(client, device, 411)
    with db.SessionLocal() as s:
        first = s.scalar(select(AuditEvent).where(AuditEvent.action == "seal").order_by(AuditEvent.id))
        s.execute(update(AuditEvent).where(AuditEvent.id == first.id).values(result="rejected:403"))
        s.commit()
    result = _check(client)
    assert result["ok"] is False and first.id in result["broken"]


def test_deleting_an_audit_row_is_detected(client, device):
    for seed in range(3):
        _seal(client, device, 420 + seed)
    with db.SessionLocal() as s:
        ids = s.scalars(select(AuditEvent.id).order_by(AuditEvent.id)).all()
        s.execute(delete(AuditEvent).where(AuditEvent.id == ids[1]))
        s.commit()
    result = _check(client)
    assert result["ok"] is False and ids[2] in result["broken"]  # its predecessor is gone


def test_concurrent_actions_never_fail_because_of_the_audit_chain(client, device):
    images = [xray_png(seed=430 + i) for i in range(10)]
    with ThreadPoolExecutor(max_workers=10) as pool:
        codes = list(pool.map(lambda data: client.post(
            "/api/seal", files={"file": ("x.png", data)}, headers=device["auth"]).status_code, images))
    assert codes == [200] * 10
    result = _check(client)
    assert result["ok"] is True and result["linked"] == result["entries"]


def test_audit_check_is_admin_only(client):
    assert client.get("/api/audit/check").status_code == 401

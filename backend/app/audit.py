"""Audit log helper. The caller commits (so the event lands together with what it describes).

Tamper evidence (review round 1): rows are hash-chained like the seal ledger,
entry_hash = sha256(prev_hash + canonical row), so deleting or editing a row shows up in
GET /audit/check. Linking happens right after the caller's commit, in its own short transaction
under a lock (process lock + PostgreSQL advisory lock): linking inside the caller's transaction
would make concurrent actions race for the chain head, and the audit trail must never make the
action it records fail. Limits, as for the ledger without its anchors: an insider who rewrites
the whole chain consistently, or deletes the newest rows, is not caught by the chain alone.
"""
import hashlib
import json
import logging
import threading

from fastapi import Request
from sqlalchemy import event, select, text
from sqlalchemy.orm import Session

from app.models import AuditEvent, iso_utc

log_ = logging.getLogger(__name__)
GENESIS = "0" * 64
AUDIT_LOCK_KEY = 0x4D4541554454  # "MEAUDT": PostgreSQL advisory lock id for linking
_link_lock = threading.Lock()


def client_ip(request: Request | None) -> str | None:
    return request.client.host if request is not None and request.client else None


def log(session: Session, action: str, actor: str, target: str = "", result: str = "",
        ip: str | None = None) -> None:
    session.add(AuditEvent(action=action, actor=actor[:200], target=target[:200], result=result[:64], ip=ip))
    session.info["audit_pending"] = True


def record_bytes(e: AuditEvent) -> bytes:
    return json.dumps(
        {"id": e.id, "at": iso_utc(e.at), "action": e.action, "actor": e.actor, "target": e.target,
         "result": e.result, "ip": e.ip},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()


def entry_hash(prev_hash: str, e: AuditEvent) -> str:
    return hashlib.sha256(prev_hash.encode() + record_bytes(e)).hexdigest()


def link_pending(session: Session) -> int:
    """Chain every not-yet-linked row, in id order, onto the newest linked one. -> rows linked."""
    with _link_lock:
        if session.get_bind().dialect.name == "postgresql":
            session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": AUDIT_LOCK_KEY})
        head = session.scalar(select(AuditEvent).where(AuditEvent.entry_hash != "").order_by(AuditEvent.id.desc()).limit(1))
        prev = head.entry_hash if head else GENESIS
        pending = session.scalars(select(AuditEvent).where(AuditEvent.entry_hash == "").order_by(AuditEvent.id)).all()
        for e in pending:
            e.prev_hash, e.entry_hash = prev, entry_hash(prev, e)
            prev = e.entry_hash
        session.commit()
        return len(pending)


def check(session: Session) -> dict:
    """Walk the chain: rows whose content or link was changed, or whose predecessor was deleted."""
    broken, prev, linked, total = [], GENESIS, 0, 0
    for e in session.scalars(select(AuditEvent).order_by(AuditEvent.id)):
        total += 1
        if not e.entry_hash:
            continue  # committed a moment ago, about to be linked
        linked += 1
        if e.prev_hash != prev or entry_hash(e.prev_hash, e) != e.entry_hash:
            broken.append(e.id)
        prev = e.entry_hash
    return {"ok": not broken, "entries": total, "linked": linked, "broken": broken}


@event.listens_for(Session, "after_commit")
def _link_after_commit(session: Session) -> None:
    if not session.info.pop("audit_pending", False):
        return
    bind = session.get_bind()
    try:
        with Session(bind=bind) as linker:
            link_pending(linker)
    except Exception:  # never let the audit chain fail the action it records
        log_.exception("audit chain linking failed; it is retried on the next commit")


def listing(session: Session, limit: int = 200, action: str | None = None) -> list[dict]:
    q = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
    if action:
        q = q.where(AuditEvent.action == action)
    return [
        {"id": e.id, "at": iso_utc(e.at), "action": e.action, "actor": e.actor, "target": e.target,
         "result": e.result, "ip": e.ip}
        for e in session.scalars(q)
    ]

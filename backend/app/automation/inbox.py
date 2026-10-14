"""Doctor's inbox: every incoming image is verified automatically and ranked by urgency.

The doctor never checks images by hand: green items need nothing, only red ones need a look.
  danger   tampered / forged / hidden attack found by the shield
  warning  no seal (the detective gives a probability), or sealed by a device revoked later
  ok       authentic and the shield is quiet

Two orthogonal axes, deliberately kept apart:
  state    new -> processing -> done | failed   (where the automatic pipeline got to)
  severity danger | warning | ok               (what the doctor has to do about it)
"""
import hashlib
import json
from datetime import datetime, timedelta

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app import audit, secretbox
from app.imaging import ImageError, load_image
from app.models import InboxItem, iso_utc, utcnow
from app.verify.service import verify_upload

SEVERITY_RANK = {"danger": 0, "warning": 1, "ok": 2}
# Placeholder written to status/severity while the row exists but verification has not finished.
PENDING = "processing"
# A pending row is not yet known to be a problem, so it sorts last; counts only cover real triage.
_SQL_RANK = SEVERITY_RANK | {PENDING: 3}
# Every code /verify and the imaging layer can attach to a result, so the feed can name the actual
# cause instead of only "tampered". Kept in sync with app/verify/service.py, app/imaging.py and the
# frontend dictionary (dictionary.inbox.reasons).
REASON_CODES = frozenset({
    "unknown_device", "untrusted_device", "bad_signature", "ledger_entry_modified",
    "device_revoked", "blockchain_mismatch",                            # -> forged
    "patient_mismatch", "seal_id_removed", "metadata_changed",           # -> tampered
    "device_not_certified", "device_revoked_later", "seal_id_missing",  # non-fatal warnings
    "burned_in_annotation",                                              # PHI visible in the pixels
    "unreadable",                                                        # raised here, not by /verify
})
LISTING_FIELDS = ("device", "changed_tiles", "detective_probability", "risk", "error")


def triage(result: dict) -> tuple[str, list[str]]:
    """-> (severity, reason codes) for a /verify result.

    A tampered/forged item is reported with its actual cause (bad signature, blockchain mismatch,
    changed patient binding, ...) when /verify named one, so the doctor is told what happened
    instead of only that something did.
    """
    status = result["status"]
    reason = result.get("reason")
    reasons: list[str] = []
    if status in ("tampered", "forged"):
        reasons.append(reason if reason in REASON_CODES else status)
    if (result.get("shield") or {}).get("attack_suspected"):
        reasons.append("attack_suspected")
    if result.get("phi_warning") in REASON_CODES:
        reasons.append(result["phi_warning"])
    if reasons:
        return "danger", reasons
    if status == "unsigned":
        return "warning", ["unsigned"]
    if result.get("warning"):
        return "warning", [result["warning"]]
    return "ok", []


def _risk(result: dict) -> str | None:
    """AI reading's overall advice (high/medium/none), only when the image was trusted and read."""
    analysis = result.get("analysis") or {}
    return analysis.get("risk") if analysis.get("status") == "done" else None


def _summarize(result: dict) -> dict:
    return {
        "risk": _risk(result),
        "device": result.get("device"),
        "changed_tiles": len(result.get("changed_tiles") or []),
        "detective_probability": (result.get("detective") or {}).get("probability"),
        "error": result.get("error"),
    }


def find_folder_item(session: Session, file_name: str, content_sha256: str) -> InboxItem | None:
    """The row this exact watched file already produced, if any.

    The watcher commits the inbox row before moving the file out of incoming/, so a crash in
    between would otherwise re-verify the same file and add a second, identical row to the
    doctor's feed. Keyed on file name AND content hash: scanners reuse names like scan.png, and a
    new image under an old name must get its own row — reusing the old one would silently replace
    the doctor's earlier verdict and clear its "reviewed" mark. Uploads are never deduplicated.
    """
    return session.scalar(
        select(InboxItem)
        .where(InboxItem.source == "folder", InboxItem.file_name == file_name[:300],
               InboxItem.content_sha256 == content_sha256)
        .order_by(InboxItem.id.desc())
        .limit(1)
    )


def process(session: Session, data: bytes, file_name: str, source: str) -> InboxItem:
    """Verify one file and store it in the inbox. Unreadable files become red 'error' items.

    Raises nothing for a bad image: an unreadable file is a triage outcome the doctor must see,
    not a crash. The caller (watcher) is responsible for its own I/O errors.
    """
    digest = hashlib.sha256(data).hexdigest()
    item = find_folder_item(session, file_name, digest) if source == "folder" else None
    if item is None:
        item = InboxItem(file_name=file_name[:300], source=source, content_sha256=digest, state="processing",
                         status=PENDING, severity=PENDING)
        session.add(item)
    else:
        item.state, item.status, item.severity = "processing", PENDING, PENDING
        item.reviewed = False
    session.commit()  # the row exists before the expensive part, so a crash is visible as "processing"

    try:
        result = verify_upload(session, load_image(data), actor=f"inbox:{source}")
        severity, reasons = triage(result)
        status = result["status"]
        state = "done"
    except ImageError as e:
        result, severity, reasons, status, state = {"error": str(e)}, "danger", ["unreadable"], "error", "failed"

    item.status = status
    item.severity = severity
    item.state = state
    item.reasons_json = json.dumps(reasons)
    store_result(item, result)
    item.summary_json = json.dumps(_summarize(result))
    session.commit()
    return item


def summary(item: InboxItem) -> dict:
    stored = json.loads(item.summary_json) if item.summary_json and item.summary_json != "{}" else None
    if stored is None:
        # Rows written before summary_json existed: fall back to the full result, once per row.
        stored = _summarize(load_result(item))
    return {
        "id": item.id,
        "file_name": item.file_name,
        "source": item.source,
        "state": item.state or "done",
        "received_at": iso_utc(item.received_at),
        "status": item.status,
        "severity": item.severity,
        "reasons": json.loads(item.reasons_json or "[]"),
        "reviewed": item.reviewed,
        "device": stored.get("device"),
        "changed_tiles": stored.get("changed_tiles", 0),
        "detective_probability": stored.get("detective_probability"),
        "risk": stored.get("risk"),
        "error": stored.get("error"),
    }


def detail(item: InboxItem) -> dict:
    return summary(item) | {"result": load_result(item)}


# --- patient data at rest ----------------------------------------------------------------------
# result_json holds the full /verify answer, including a rendered preview of the patient's image:
# it is stored encrypted (app/secretbox.py, bound to the row id), and the preview is dropped after
# MEDSEAL_INBOX_PREVIEW_DAYS (the verdict, reasons and summary stay: they are the medical record).
ENC_PREFIX = "enc1:"
IMAGE_KEYS = ("preview_png", "heatmap_png")


def _aad(item: InboxItem) -> bytes:
    return f"inbox-result:{item.id}".encode()


def store_result(item: InboxItem, result: dict) -> None:
    item.result_json = ENC_PREFIX + secretbox.encrypt_text(json.dumps(result), _aad(item))


def load_result(item: InboxItem) -> dict:
    raw = item.result_json or "{}"
    if raw.startswith(ENC_PREFIX):
        raw = secretbox.decrypt_text(raw[len(ENC_PREFIX):], _aad(item))
    return json.loads(raw)


def purge_previews(session: Session, days: float) -> int:
    """Drop the stored image previews of items older than `days`; -> how many were purged."""
    if days <= 0:
        return 0
    cutoff = utcnow() - timedelta(days=days)
    purged = 0
    for item in session.scalars(select(InboxItem).where(InboxItem.received_at < cutoff,
                                                        InboxItem.preview_purged_at.is_(None))):
        result = load_result(item)
        for key in IMAGE_KEYS:
            result.pop(key, None)
        store_result(item, result)
        item.preview_purged_at = utcnow()
        purged += 1
    if purged:
        audit.log(session, "inbox_retention", "scheduler", result=f"previews purged: {purged}")
    session.commit()
    return purged


def _volume(session: Session) -> dict:
    """How many checks actually finished (not still "processing"), today / this week / ever —
    a raw activity count for the doctor's summary tiles, independent of the danger/warning/ok mix."""
    now = utcnow()
    done = InboxItem.state != "processing"

    def count(since: datetime | None = None) -> int:
        q = select(func.count()).select_from(InboxItem).where(done)
        if since is not None:
            q = q.where(InboxItem.received_at >= since)
        return session.scalar(q) or 0

    return {"today": count(now - timedelta(hours=24)), "week": count(now - timedelta(days=7)), "all": count()}


def listing(session: Session, limit: int = 200, severity: str | None = None, reviewed: bool | None = None,
            since: datetime | None = None, until: datetime | None = None, offset: int = 0) -> dict:
    """Unreviewed first, then most urgent, then newest. Optional filters for the doctor's filters."""
    rank = case(_SQL_RANK, value=InboxItem.severity, else_=3)
    q = select(InboxItem)
    counted = q
    for cond in (
        InboxItem.severity == severity if severity is not None else None,
        InboxItem.reviewed.is_(reviewed) if reviewed is not None else None,
        InboxItem.received_at >= since if since is not None else None,
        InboxItem.received_at <= until if until is not None else None,
    ):
        if cond is not None:
            q, counted = q.where(cond), counted.where(cond)
    rows = session.scalars(q.order_by(InboxItem.reviewed, rank, InboxItem.id.desc()).offset(offset).limit(limit))
    # counts are over unreviewed items only: that is the doctor's actual work queue.
    counts = dict(session.execute(
        select(InboxItem.severity, func.count())
        .where(InboxItem.reviewed.is_(False), InboxItem.severity != PENDING)
        .group_by(InboxItem.severity)
    ).all())
    return {
        "counts": {s: counts.get(s, 0) for s in SEVERITY_RANK}
        | {"total": session.scalar(select(func.count()).select_from(counted.subquery()))},
        "volume": _volume(session),
        "items": [summary(r) for r in rows],
    }

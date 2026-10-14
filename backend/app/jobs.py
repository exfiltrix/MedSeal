"""Background jobs kept in the database (crash tests), run by a worker loop.

Why: with several uvicorn workers, job state in one process's memory is invisible to the others
(a status request lands on another process and reports "interrupted"), and every process would
run its own copy of every loop. Here the API only inserts a `queued` row; whichever process runs
the worker loop claims it (FOR UPDATE SKIP LOCKED on PostgreSQL), writes progress and a heartbeat
to the row, and stores the result. A job whose heartbeat stops (the worker died) is marked
`error` after STALE_AFTER instead of hanging in `running` forever.
"""
import importlib
import json
import logging
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text, update

from app import db
from app.models import CrashTest

log = logging.getLogger(__name__)
POLL_S = 2.0
STALE_AFTER = timedelta(minutes=2)
HEARTBEAT_EVERY_S = 1.0
ENQUEUE_LOCK_KEY = 0x4D4543525348  # "MECRSH": PostgreSQL advisory lock for the one-active-job rule
ACTIVE = ("queued", "running")

_wake = threading.Event()
_stop = threading.Event()
_thread: threading.Thread | None = None
_enqueue_lock = threading.Lock()


def now() -> datetime:
    return datetime.now(timezone.utc)


class Busy(Exception):
    pass


def enqueue(session, model_id: int, params: dict) -> int:
    """Insert a queued crash test; Busy if one is already queued or running (one CPU-heavy job at
    a time, across every process)."""
    with _enqueue_lock:
        if session.get_bind().dialect.name == "postgresql":
            session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": ENQUEUE_LOCK_KEY})
        if session.scalar(select(CrashTest.id).where(CrashTest.status.in_(ACTIVE)).limit(1)) is not None:
            session.rollback()
            raise Busy()
        row = CrashTest(model_id=model_id, n_images=params["n_images"], results_json="{}", status="queued",
                        params_json=json.dumps(params), progress=0.0)
        session.add(row)
        session.commit()
    _wake.set()
    return row.id


def _claim(session) -> CrashTest | None:
    q = select(CrashTest).where(CrashTest.status == "queued").order_by(CrashTest.id).limit(1)
    if session.get_bind().dialect.name == "postgresql":
        q = q.with_for_update(skip_locked=True)
    row = session.scalar(q)
    if row is None:
        session.rollback()
        return None
    # Compare-and-set: only the one UPDATE that still finds it queued wins. With SKIP LOCKED this
    # never loses on PostgreSQL; on SQLite (no row locks) it is what keeps a job single-run.
    won = session.execute(
        update(CrashTest).where(CrashTest.id == row.id, CrashTest.status == "queued")
        .values(status="running", heartbeat_at=now())
    ).rowcount == 1
    session.commit()
    return row if won else None


def fail_stale(session) -> int:
    """Jobs whose worker stopped heartbeating: report them instead of leaving them 'running'."""
    cutoff = now() - STALE_AFTER
    result = session.execute(
        update(CrashTest)
        .where(CrashTest.status == "running", CrashTest.heartbeat_at < cutoff)
        .values(status="error", error="Job was interrupted (the worker stopped)")
    )
    session.commit()
    return result.rowcount or 0


def run_one() -> bool:
    """Claim and run the oldest queued job. -> whether one was run."""
    with db.SessionLocal() as session:
        fail_stale(session)
        row = _claim(session)
        if row is None:
            return False
        job_id, params = row.id, json.loads(row.params_json or "{}")
    last = [0.0]

    def progress(p: float) -> None:
        t = now().timestamp()
        if t - last[0] < HEARTBEAT_EVERY_S and p < 1.0:
            return
        last[0] = t
        with db.SessionLocal() as s:
            s.execute(update(CrashTest).where(CrashTest.id == job_id)
                      .values(progress=round(p, 3), heartbeat_at=now()))
            s.commit()

    try:
        crash_test = importlib.import_module("app.ai.crash_test")  # via sys.modules: torch-free fakes in tests
        result = crash_test.run(params["n_images"], params["eps"], params["method"], progress=progress)
        with db.SessionLocal() as s:
            s.execute(update(CrashTest).where(CrashTest.id == job_id).values(
                status="done", progress=1.0, n_images=result["n_images"], results_json=json.dumps(result),
                robustness_score=result["robustness_score"], heartbeat_at=now()))
            s.commit()
    except Exception as e:  # report any failure on the row instead of a job stuck in running
        log.exception("crash test %s failed", job_id)
        with db.SessionLocal() as s:
            s.execute(update(CrashTest).where(CrashTest.id == job_id).values(status="error", error=str(e)[:2000]))
            s.commit()
    return True


def _loop() -> None:
    while not _stop.is_set():
        try:
            while run_one() and not _stop.is_set():
                pass
        except Exception:
            log.exception("job loop pass failed")
        _wake.wait(POLL_S)
        _wake.clear()


def start() -> None:
    global _thread
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="medseal-jobs", daemon=True)
    _thread.start()


def stop(wait: bool = True) -> None:
    _stop.set()
    _wake.set()
    if wait and _thread is not None:
        _thread.join(timeout=10)

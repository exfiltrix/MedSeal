"""Models under test and crash-test jobs.

Jobs live in the crash_tests table (app/jobs.py): the request only validates and enqueues, the
worker loop (in this process for MEDSEAL_PROCESS_ROLE=all, or `python -m app.worker`) runs them,
and any API process can answer the status. One job at a time, across every process.
"""
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import jobs
from app.auth import require_admin
from app.db import get_session
from app.models import AIModel, CrashTest, iso_utc
from app.passport.report import protocol_compliant

router = APIRouter(tags=["crash-test"])

BUILTIN_MODEL = {
    "name": "torchxrayvision DenseNet121",
    "version": "densenet121-res224-all",
    "source": "https://github.com/mlmed/torchxrayvision",
    "intended_use": "Chest X-ray screening, 18 pathologies (research model, not a medical device)",
}


def seed_models(session: Session) -> None:
    if session.scalar(select(AIModel).where(AIModel.version == BUILTIN_MODEL["version"])) is None:
        session.add(AIModel(**BUILTIN_MODEL))
        session.commit()


def model_json(m: AIModel) -> dict:
    return {"id": m.id, "name": m.name, "version": m.version, "source": m.source, "intended_use": m.intended_use}


@router.get("/models")
def list_models(session: Session = Depends(get_session)):
    return [model_json(m) for m in session.scalars(select(AIModel).order_by(AIModel.id))]


class CrashTestIn(BaseModel):
    model_id: int
    n_images: int = Field(default=50, ge=1, le=200)
    eps: list[float] = Field(default=[0.5, 1, 2, 4], min_length=1, max_length=8)
    method: Literal["fgsm", "pgd"] = "pgd"


@router.post("/crash-test", status_code=202, dependencies=[Depends(require_admin)])
def start_crash_test(body: CrashTestIn, session: Session = Depends(get_session)):
    m = session.get(AIModel, body.model_id)
    if m is None:
        raise HTTPException(404, "Model not found")
    if m.version != BUILTIN_MODEL["version"]:
        raise HTTPException(400, "Only the built-in DenseNet can be crash-tested")
    if any(not 0 < e <= 16 for e in body.eps):
        raise HTTPException(422, "eps must be in (0, 16] pixel units")
    try:
        import app.ai.crash_test  # noqa: F401
    except ImportError as e:
        raise HTTPException(503, f"AI modules are not installed: {e}") from e
    try:
        job_id = jobs.enqueue(session, m.id, {"n_images": body.n_images, "eps": body.eps, "method": body.method})
    except jobs.Busy:
        raise HTTPException(409, "A crash test is already running") from None
    return {"job_id": job_id}


@router.get("/crash-test/{job_id}")
def crash_test_status(job_id: int, session: Session = Depends(get_session)):
    row = session.get(CrashTest, job_id)
    if row is None:
        raise HTTPException(404, "Crash test not found")
    base = {"job_id": row.id, "model_id": row.model_id, "created_at": iso_utc(row.created_at)}
    if row.robustness_score is not None:
        data = json.loads(row.results_json)
        data.setdefault("n_requested", data.get("n_images", 0))
        return base | {"status": "done", "progress": 1.0, "protocol_compliant": protocol_compliant(data)} | data
    out = base | {"status": row.status, "progress": row.progress or 0.0}
    if row.status == "error":
        out["error"] = row.error or "Job failed"
    return out


@router.get("/crash-tests")
def list_crash_tests(model_id: int | None = None, session: Session = Depends(get_session)):
    """Finished crash tests, newest first (without the example images)."""
    q = select(CrashTest).where(CrashTest.robustness_score.is_not(None)).order_by(CrashTest.id.desc())
    if model_id is not None:
        q = q.where(CrashTest.model_id == model_id)
    out = []
    for row in session.scalars(q):
        r = json.loads(row.results_json)
        r.pop("example", None)
        r.setdefault("n_requested", r.get("n_images", 0))
        out.append(
            {"job_id": row.id, "model_id": row.model_id, "created_at": iso_utc(row.created_at),
             "protocol_compliant": protocol_compliant(r)} | r
        )
    return out

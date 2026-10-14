"""Crash-test jobs in the database (app/jobs.py): what several API workers + one worker need."""
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from app import db, jobs
from app.config import settings
from app.models import CrashTest
from tests.conftest import admin_headers

BODY = {"n_images": 1, "eps": [1], "method": "pgd"}


class FakeCrashTest:
    @staticmethod
    def run(n_images, eps, method, progress=None):
        progress(0.5)
        return {"n_images": n_images, "method": method, "pathology": "Pneumonia", "eps": eps,
                "flip_rate": {"1": 0.0}, "psnr": {"1": 50.0}, "robustness_score": 10.0}


@pytest.fixture
def api_only(client, monkeypatch):
    """An HTTP-only process (MEDSEAL_PROCESS_ROLE=api): it enqueues, it never runs a job."""
    from app.main import app

    monkeypatch.setitem(sys.modules, "app.ai.crash_test", FakeCrashTest)
    jobs.stop(wait=True)  # the `client` fixture's process runs the loop (role all): stop it
    monkeypatch.setattr(settings, "process_role", "api")
    with TestClient(app) as c:
        yield c


def _model_id(c):
    return c.get("/api/models").json()[0]["id"]


def test_api_process_only_enqueues_and_any_process_reports_progress(api_only):
    job = api_only.post("/api/crash-test", json=BODY | {"model_id": _model_id(api_only)}, headers=admin_headers())
    assert job.status_code == 202
    job_id = job.json()["job_id"]
    assert api_only.get(f"/api/crash-test/{job_id}").json()["status"] == "queued"  # nobody ran it
    assert jobs.run_one() is True  # the worker process
    done = api_only.get(f"/api/crash-test/{job_id}").json()
    assert done["status"] == "done" and done["robustness_score"] == 10.0
    assert jobs.run_one() is False  # nothing left


def test_one_active_job_across_processes(api_only):
    body = BODY | {"model_id": _model_id(api_only)}
    assert api_only.post("/api/crash-test", json=body, headers=admin_headers()).status_code == 202
    assert api_only.post("/api/crash-test", json=body, headers=admin_headers()).status_code == 409


def test_a_job_whose_worker_died_is_reported(api_only):
    job_id = api_only.post("/api/crash-test", json=BODY | {"model_id": _model_id(api_only)},
                           headers=admin_headers()).json()["job_id"]
    with db.SessionLocal() as s:
        s.execute(update(CrashTest).where(CrashTest.id == job_id).values(
            status="running", heartbeat_at=jobs.now() - jobs.STALE_AFTER - timedelta(seconds=1)))
        s.commit()
        assert jobs.fail_stale(s) == 1
    status = api_only.get(f"/api/crash-test/{job_id}").json()
    assert status["status"] == "error" and "interrupted" in status["error"]


def test_two_workers_never_run_the_same_job(api_only):
    """FOR UPDATE SKIP LOCKED on PostgreSQL; SQLite serialises writers itself."""
    api_only.post("/api/crash-test", json=BODY | {"model_id": _model_id(api_only)}, headers=admin_headers())
    with ThreadPoolExecutor(max_workers=4) as pool:
        ran = list(pool.map(lambda _: jobs.run_one(), range(4)))
    assert ran.count(True) == 1

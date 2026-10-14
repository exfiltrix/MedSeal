"""Health checks and structured logging for operations (review: production readiness).

- GET /api/health/live  — the process answers (for the orchestrator's restart decision).
- GET /api/health/ready — it can actually serve: database reachable, schema at the latest
  migration, trust root present. 503 lists which check failed, never a secret or a stack trace.
- Every request gets an X-Request-ID (taken from the proxy if it sent one), echoed in the
  response and in every log line. MEDSEAL_LOG_FORMAT=json (default in production) writes one JSON
  object per line for the log collector. Logs carry no image data and no patient identifiers.
"""
import contextvars
import json
import logging
import os
import re
import time
import uuid

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app import db
from app.config import settings

request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
router = APIRouter(tags=["health"])
access_log = logging.getLogger("medseal.access")
# Capability tokens travel in some paths (public QR check): never write them to a log.
_SECRET_PATH = re.compile(r"(/api/check/)[^/]+")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id.get(),
        }
        for key in ("method", "path", "status", "ms"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id.get()
        return True


def configure_logging() -> None:
    fmt = os.environ.get("MEDSEAL_LOG_FORMAT", "json" if settings.production else "text")
    handler = logging.StreamHandler()
    handler.addFilter(_RequestIdFilter())
    handler.setFormatter(JsonFormatter() if fmt == "json" else
                         logging.Formatter("%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s"))
    handler.set_name("medseal")
    root = logging.getLogger()
    # Replace only our own handler (startup may run more than once); leave the server's and the
    # test runner's handlers alone.
    root.handlers[:] = [h for h in root.handlers if h.get_name() != "medseal"] + [handler]
    root.setLevel(os.environ.get("MEDSEAL_LOG_LEVEL", "INFO"))


def install(app: FastAPI) -> None:
    @app.middleware("http")
    async def with_request_id(req: Request, call_next):
        incoming = req.headers.get("x-request-id", "")
        rid = incoming if _REQUEST_ID.match(incoming) else uuid.uuid4().hex
        token = request_id.set(rid)
        t0 = time.perf_counter()
        try:
            response = await call_next(req)
            response.headers["X-Request-ID"] = rid
            access_log.info("request", extra={"method": req.method, "path": _SECRET_PATH.sub(r"\1***", req.url.path),
                                              "status": response.status_code,
                                              "ms": round((time.perf_counter() - t0) * 1000, 1)})
            return response
        finally:
            request_id.reset(token)


@router.get("/health/live")
@router.get("/health")
def live():
    return {"ok": True}


@router.get("/health/ready")
def ready():
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    checks = {}
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            cfg = Config()
            cfg.set_main_option("script_location", str(db.MIGRATIONS_DIR))
            head = ScriptDirectory.from_config(cfg).get_current_head()
            checks["schema"] = MigrationContext.configure(conn).get_current_revision() == head
        checks["database"] = True
    except Exception:  # noqa: BLE001 - readiness reports, it does not crash
        checks.update(database=False, schema=False)
    checks["trust_root"] = settings.root_pubkey_path.exists()
    ok = all(checks.values())
    return JSONResponse({"ok": ok, "checks": checks}, status_code=200 if ok else 503)

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import db, hardening, jobs, observability, security
from app.config import settings
from app.db import init_engine
from app.anchor import chain as anchor_chain, service as anchoring
from app.automation import warmup, watcher
from app.routers import accounts, anchors, audit, check, clients, crash_test, devices, inbox, passport, seal, stats, verify
from app.seal.recovery import backfill_dhash


def _read_sealed_file(row) -> bytes | None:
    path = settings.storage_dir / row.file_name
    return path.read_bytes() if path.exists() else None


def prepare() -> None:
    """Startup shared by the API and the worker process: checks, schema, seed data, backfills."""
    observability.configure_logging()
    hardening.check_on_startup()  # MEDSEAL_ENV=production: refuse to start on an unsafe configuration
    init_engine()
    with db.SessionLocal() as session:
        crash_test.seed_models(session)
        # P1-03: fills dhash_hex for rows sealed before this column existed. Read-only over the
        # stored files, writes only dhash_hex — never a hashed/signed field.
        backfill_dhash(session, _read_sealed_file)


def start_background() -> None:
    """The loops that must run in exactly one process: folder watcher, anchoring, job worker."""
    if settings.watch_enabled:
        watcher.start()
    if anchor_chain.configured():
        with db.SessionLocal() as session:
            anchoring.resync_local_chain(session)  # local Hardhat node restarted since last run
    if settings.anchor_enabled and anchor_chain.configured():
        anchoring.start()
    jobs.start()


def stop_background() -> None:
    jobs.stop(wait=True)
    watcher.stop()
    anchoring.stop()


@asynccontextmanager
async def lifespan(app: FastAPI):
    prepare()
    if settings.warmup:  # the API answers /verify with the shield, so the model is loaded here
        warmup.start()
    # MEDSEAL_PROCESS_ROLE=api: several uvicorn workers serve HTTP and `python -m app.worker` runs
    # the loops once; "all" keeps everything in this one process (development, a single server).
    background = settings.process_role == "all"
    if background:
        start_background()
    try:
        yield
    finally:
        if background:
            stop_background()


# Production: no interactive API explorer on the public surface (it maps every endpoint for an attacker).
_docs = {} if not settings.production else {"docs_url": None, "redoc_url": None, "openapi_url": None}
app = FastAPI(title="MedSeal API", version="0.1.0", lifespan=lifespan, **_docs)
security.install(app)  # before CORS: CORS must stay the outermost middleware
observability.install(app)  # request id on every request and log line
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=settings.cors_origin_regex or None,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "X-Request-ID"],
)

for r in (devices.router, seal.router, verify.router, inbox.router, check.router, crash_test.router, passport.router,
          stats.router, anchors.router, audit.router, clients.router, observability.router, accounts.router):
    app.include_router(r, prefix="/api")



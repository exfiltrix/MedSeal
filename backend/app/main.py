from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import db, hardening, observability, security
from app.config import settings
from app.db import init_engine
from app.anchor import chain as anchor_chain, service as anchoring
from app.automation import warmup, watcher
from app.routers import accounts, anchors, audit, check, clients, crash_test, devices, inbox, passport, seal, stats, verify
from app.seal.recovery import backfill_dhash


def _read_sealed_file(row) -> bytes | None:
    path = settings.storage_dir / row.file_name
    return path.read_bytes() if path.exists() else None


@asynccontextmanager
async def lifespan(app: FastAPI):
    observability.configure_logging()
    hardening.check_on_startup()  # MEDSEAL_ENV=production: refuse to start on an unsafe configuration
    init_engine()
    with db.SessionLocal() as session:
        crash_test.seed_models(session)
        # P1-03: fills dhash_hex for rows sealed before this column existed. Read-only over the
        # stored files, writes only dhash_hex — never a hashed/signed field.
        backfill_dhash(session, _read_sealed_file)
    if settings.warmup:
        warmup.start()
    if settings.watch_enabled:
        watcher.start()
    if anchor_chain.configured():
        with db.SessionLocal() as session:
            anchoring.resync_local_chain(session)  # local Hardhat node restarted since last run
    if settings.anchor_enabled and anchor_chain.configured():
        anchoring.start()
    try:
        yield
    finally:
        crash_test.shutdown_worker(wait=True)
        watcher.stop()
        anchoring.stop()


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



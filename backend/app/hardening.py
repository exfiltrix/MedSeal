"""Production startup checks: with MEDSEAL_ENV=production the backend refuses to start on any
setting that is fine on a developer laptop but unsafe with real patients' data.

Fail closed: every problem is listed at once, then startup aborts. Developer mode only logs them.
Run without starting the server: python -m app.hardening
"""
import logging
import sys
from urllib.parse import urlparse

from app.config import settings

log = logging.getLogger(__name__)
MIN_SECRET_LEN = 32
LOCAL_CHAIN_IDS = {31337, 1337}
PLACEHOLDERS = {"change-me", "change-me-too", "dev-admin-token", "test-admin-token", "secret", "password"}


class InsecureConfiguration(RuntimeError):
    pass


def _weak(secret: str) -> bool:
    return len(secret) < MIN_SECRET_LEN or secret.lower() in PLACEHOLDERS


def problems() -> list[str]:
    """Everything that makes the current configuration unfit for production."""
    out = []
    if not settings.db_url.startswith("postgresql"):
        out.append("MEDSEAL_DB_URL must point to PostgreSQL (SQLite is for the offline demo only)")
    if _weak(settings.patient_salt):
        out.append(f"MEDSEAL_PATIENT_SALT must be a random secret of at least {MIN_SECRET_LEN} characters "
                   "(without it a patient swap between images is not detected)")
    for name, value in (("MEDSEAL_ADMIN_TOKEN", settings.admin_token), ("MEDSEAL_DOCTOR_TOKEN", settings.doctor_token)):
        if value:
            out.append(f"{name} must be empty: people sign in with personal accounts "
                       "(python -m scripts.create_user), a shared token cannot say who acted")
    if not settings.data_key:
        out.append("MEDSEAL_DATA_KEY must come from the secret manager (a generated key file next to the "
                   "data it protects is for development only)")
    if not settings.require_device_cert:
        out.append("MEDSEAL_REQUIRE_DEVICE_CERT=0 is a migration mode: uncertified devices must fail verification")
    if settings.rate_limit_per_min <= 0:
        out.append("MEDSEAL_RATE_LIMIT must be > 0")
    if settings.cors_origin_regex:
        out.append("MEDSEAL_CORS_ORIGIN_REGEX must be empty: list the exact site origins in MEDSEAL_CORS_ORIGINS")
    for origin in filter(None, (o.strip() for o in settings.cors_origins)):
        if urlparse(origin).scheme != "https":
            out.append(f"CORS origin {origin!r} must use https")
    if not (settings.rpc_url and settings.contract_address and settings.anchor_private_key):
        out.append("blockchain anchoring must be configured (RPC_URL, CONTRACT_ADDRESS, ANCHOR_PRIVATE_KEY): "
                   "it is what catches an insider rewriting the ledger")
    elif settings.chain_id in LOCAL_CHAIN_IDS:
        out.append(f"CHAIN_ID {settings.chain_id} is a local development chain")
    return out


def check_on_startup() -> None:
    found = problems()
    if not found:
        return
    message = "insecure configuration:\n  - " + "\n  - ".join(found)
    if settings.production:
        raise InsecureConfiguration(message)
    log.warning("%s\n(development mode: starting anyway; MEDSEAL_ENV=production refuses)", message)


if __name__ == "__main__":
    found = problems()
    print("OK: fit for production" if not found else "NOT fit for production:\n  - " + "\n  - ".join(found))
    sys.exit(1 if found else 0)

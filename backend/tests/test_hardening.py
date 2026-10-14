"""MEDSEAL_ENV=production refuses to start on an unsafe configuration (app/hardening.py)."""
import pytest

from app import hardening
from app.config import settings

STRONG = "x" * 40


@pytest.fixture
def production_ready(monkeypatch, tmp_path):
    """A configuration that passes every check; each test breaks exactly one thing."""
    for name, value in {
        "env": "production",
        "db_url": "postgresql+psycopg://medseal:pw@db/medseal",
        "patient_salt": STRONG,
        "admin_token": "",
        "doctor_token": "",
        "require_device_cert": True,
        "rate_limit_per_min": 120,
        "cors_origin_regex": "",
        "cors_origins": ["https://medseal.example.uz"],
        "rpc_url": "https://rpc.example",
        "contract_address": "0x" + "1" * 40,
        "anchor_private_key": STRONG,
        "chain_id": 11155111,
        "data_key": "k" * 44,
        "key_backend": "file",
        "allow_software_keys": True,
        "inbox_preview_days": 90,
        "process_role": "api",
        "keys_dir": tmp_path / "keys",
        "root_key_path": tmp_path / "keys" / "root.pem",
    }.items():
        monkeypatch.setattr(settings, name, value)
    assert hardening.problems() == []
    return monkeypatch


@pytest.mark.parametrize("name,value,expected", [
    ("db_url", "sqlite:///medseal.db", "PostgreSQL"),
    ("patient_salt", "", "MEDSEAL_PATIENT_SALT"),
    ("patient_salt", "change-me", "MEDSEAL_PATIENT_SALT"),
    ("admin_token", "x" * 64, "MEDSEAL_ADMIN_TOKEN"),
    ("doctor_token", "short", "MEDSEAL_DOCTOR_TOKEN"),
    ("data_key", "", "MEDSEAL_DATA_KEY"),
    ("require_device_cert", False, "MEDSEAL_REQUIRE_DEVICE_CERT"),
    ("rate_limit_per_min", 0, "MEDSEAL_RATE_LIMIT"),
    ("cors_origin_regex", r"http://192\.168\..*", "MEDSEAL_CORS_ORIGIN_REGEX"),
    ("cors_origins", ["http://medseal.example.uz"], "https"),
    ("rpc_url", "", "anchoring must be configured"),
    ("chain_id", 31337, "local development chain"),
    ("allow_software_keys", False, "MEDSEAL_KEY_BACKEND=pkcs11"),
    ("key_backend", "vault", "use 'file' or 'pkcs11'"),
    ("inbox_preview_days", 0, "MEDSEAL_INBOX_PREVIEW_DAYS"),
    ("process_role", "everything", "MEDSEAL_PROCESS_ROLE"),
])
def test_each_unsafe_setting_is_named(production_ready, name, value, expected):
    production_ready.setattr(settings, name, value)
    found = hardening.problems()
    assert len(found) == 1 and expected in found[0], found


def test_production_refuses_to_start(production_ready):
    production_ready.setattr(settings, "db_url", "sqlite:///medseal.db")
    with pytest.raises(hardening.InsecureConfiguration, match="PostgreSQL"):
        hardening.check_on_startup()


def test_development_only_warns(production_ready, caplog):
    production_ready.setattr(settings, "env", "development")
    production_ready.setattr(settings, "db_url", "sqlite:///medseal.db")
    hardening.check_on_startup()  # no exception
    assert "insecure configuration" in caplog.text


def test_production_app_does_not_start_with_sqlite(client, monkeypatch):
    """The real lifespan runs the check before touching the database."""
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setattr(settings, "db_url", "sqlite:///never-created.db")
    with pytest.raises(hardening.InsecureConfiguration):
        with TestClient(app):
            pass


def test_hsm_backend_needs_its_configuration(production_ready):
    production_ready.setattr(settings, "key_backend", "pkcs11")
    found = hardening.problems()
    assert len(found) == 1 and "MEDSEAL_PKCS11_LIB" in found[0]


def test_plaintext_key_files_block_production(production_ready, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "device_7.pem").write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    found = hardening.problems()
    assert len(found) == 1 and "scripts.encrypt_keys" in found[0]

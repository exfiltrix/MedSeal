"""Personal accounts (app/accounts.py, app/routers/accounts.py): who may do what, and that every
way in or around sign-in fails closed."""
from datetime import timedelta

import pyotp
import pytest
from sqlalchemy import select, update

from app import accounts, db, security
from app.config import settings
from app.models import User, UserSession
from tests.conftest import admin_headers

PW = "correct horse battery"
NEW_PW = "another long passphrase"


def _create(client, username, role, **extra):
    r = client.post("/api/users", json={"username": username, "role": role, "password": PW, **extra},
                    headers=admin_headers())
    assert r.status_code == 201, r.text
    return r.json()


def _login(client, username, password=PW, totp=None):
    return client.post("/api/auth/login", json={"username": username, "password": password, "totp": totp})


def _signed_in(client, username, role, **extra):
    """Created, first sign-in, password changed: a ready session header."""
    created = _create(client, username, role, **extra)
    code = pyotp.parse_uri(created["mfa_provisioning_uri"]).now() if "mfa_provisioning_uri" in created else None
    token = _login(client, username, totp=code).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/auth/password", json={"current": PW, "new": NEW_PW}, headers=h).status_code == 200
    return h


def test_first_sign_in_must_change_the_password(client):
    _create(client, "dilnoza", "doctor")
    r = _login(client, "dilnoza")
    assert r.status_code == 200 and r.json()["user"]["must_change_password"] is True
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    assert client.get("/api/inbox", headers=h).status_code == 403  # nothing else until it is changed
    assert client.get("/api/auth/me", headers=h).status_code == 200
    r = client.post("/api/auth/password", json={"current": PW, "new": "short"}, headers=h)
    assert r.status_code == 422
    assert client.post("/api/auth/password", json={"current": PW, "new": NEW_PW}, headers=h).status_code == 200
    assert client.get("/api/inbox", headers=h).status_code == 200


def test_admin_needs_a_valid_totp_code(client):
    created = _create(client, "rustam", "admin")
    totp = pyotp.parse_uri(created["mfa_provisioning_uri"])
    assert _login(client, "rustam").status_code == 401  # password alone is not enough
    assert _login(client, "rustam", totp="000000").status_code == 401
    assert _login(client, "rustam", totp=totp.now()).status_code == 200


def test_a_totp_code_cannot_be_replayed(client):
    created = _create(client, "nodira", "admin")
    code = pyotp.parse_uri(created["mfa_provisioning_uri"]).now()
    assert _login(client, "nodira", totp=code).status_code == 200
    assert _login(client, "nodira", totp=code).status_code == 401  # same code, same window


def test_wrong_password_and_unknown_user_look_the_same(client):
    _create(client, "aziz", "doctor")
    a, b = _login(client, "aziz", password="wrong password!!"), _login(client, "nobody-here")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_account_locks_after_repeated_failures(client, monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 3)
    _create(client, "kamola", "doctor")
    for _ in range(3):
        assert _login(client, "kamola", password="wrong password!!").status_code == 401
    r = _login(client, "kamola")  # even the right password while locked
    assert r.status_code == 401 and "locked" in r.json()["detail"]
    with db.SessionLocal() as s:  # the lock runs out
        s.execute(update(User).where(User.username == "kamola").values(locked_until=accounts.now() - timedelta(seconds=1)))
        s.commit()
    assert _login(client, "kamola").status_code == 200


def test_roles_are_enforced(client, device):
    doctor = _signed_in(client, "doc1", "doctor")
    auditor = _signed_in(client, "aud1", "auditor")
    assert client.get("/api/inbox", headers=doctor).status_code == 200
    assert client.post("/api/devices", json={"name": "X"}, headers=doctor).status_code == 403
    assert client.get("/api/users", headers=doctor).status_code == 403
    assert client.get("/api/audit", headers=doctor).status_code == 403
    assert client.get("/api/audit", headers=auditor).status_code == 200
    assert client.get("/api/inbox", headers=auditor).status_code == 403


def test_client_sees_only_its_own_hospital(client, device):
    """The `device` fixture belongs to Namangan; an Andijon client asking for Namangan via ?org=
    still gets only Andijon (an empty list), the Namangan client gets the device."""
    andijon = _signed_in(client, "clinic1", "client", hospital="Andijon klinikasi")
    namangan = _signed_in(client, "clinic2", "client", hospital="Namangan viloyat shifoxonasi")
    r = client.get("/api/client/devices?org=Namangan viloyat shifoxonasi", headers=andijon)
    assert r.status_code == 200 and r.json() == []
    assert [d["name"] for d in client.get("/api/client/devices", headers=namangan).json()] == ["KT-01"]


def test_logout_and_deactivation_revoke_sessions(client):
    h = _signed_in(client, "doc2", "doctor")
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401

    h = {"Authorization": f"Bearer {_login(client, 'doc2', NEW_PW).json()['token']}"}
    uid = client.get("/api/auth/me", headers=h).json()["id"]
    assert client.post(f"/api/users/{uid}/deactivate", headers=admin_headers()).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401
    assert _login(client, "doc2", NEW_PW).status_code == 401


def test_idle_and_absolute_expiry(client):
    h = _signed_in(client, "doc3", "doctor")
    with db.SessionLocal() as s:
        s.execute(update(UserSession).values(last_seen_at=accounts.now() - timedelta(minutes=settings.session_idle_minutes + 1)))
        s.commit()
    assert client.get("/api/auth/me", headers=h).status_code == 401
    h = {"Authorization": f"Bearer {_login(client, 'doc3', NEW_PW).json()['token']}"}
    with db.SessionLocal() as s:
        s.execute(update(UserSession).values(expires_at=accounts.now() - timedelta(seconds=1)))
        s.commit()
    assert client.get("/api/auth/me", headers=h).status_code == 401


def test_only_hashes_are_stored(client):
    created = _create(client, "doc4", "doctor")
    token = _login(client, "doc4").json()["token"]
    with db.SessionLocal() as s:
        user = s.get(User, created["id"])
        row = s.scalar(select(UserSession).where(UserSession.user_id == user.id))
    assert PW not in user.password_hash and user.password_hash.startswith("$argon2id$")
    assert row.token_hash != token and len(row.token_hash) == 64


def test_admin_mfa_secret_is_encrypted_at_rest(client):
    created = _create(client, "admin2", "admin")
    secret = pyotp.parse_uri(created["mfa_provisioning_uri"]).secret
    with db.SessionLocal() as s:
        stored = s.get(User, created["id"]).mfa_secret_enc
    assert stored and secret not in stored


def test_password_change_revokes_other_sessions(client):
    h1 = _signed_in(client, "doc5", "doctor")
    h2 = {"Authorization": f"Bearer {_login(client, 'doc5', NEW_PW).json()['token']}"}
    r = client.post("/api/auth/password", json={"current": NEW_PW, "new": "a third long passphrase"}, headers=h2)
    assert r.status_code == 200
    assert client.get("/api/auth/me", headers=h1).status_code == 401  # the other browser is out
    assert client.get("/api/auth/me", headers=h2).status_code == 200


def test_actions_are_audited_by_name(client):
    h = _signed_in(client, "doc6", "doctor")
    client.post("/api/automation/run", headers=h)
    actors = {r["actor"] for r in client.get("/api/audit?limit=100", headers=admin_headers()).json()}
    assert {"user:doc6"} <= actors


def test_login_has_a_strict_rate_limit(client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_min", 120)
    security.reset_rate_limit()
    try:
        codes = [_login(client, "nobody", password="x" * 12).status_code for _ in range(11)]
        assert codes[:10] == [401] * 10 and codes[10] == 429
    finally:
        security.reset_rate_limit()


@pytest.mark.parametrize("payload,status", [
    ({"username": "x1", "role": "superuser", "password": PW}, 422),
    ({"username": "x2", "role": "client", "password": PW}, 422),  # client needs a hospital
    ({"username": "x3", "role": "doctor", "password": "short"}, 422),
    ({"username": "x4", "role": "doctor", "password": "x4 is in this password"}, 422),
])
def test_bad_accounts_are_refused(client, payload, status):
    assert client.post("/api/users", json=payload, headers=admin_headers()).status_code == status

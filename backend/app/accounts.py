"""Personal accounts, sign-in and sessions (review: production — replaces shared role tokens).

- Passwords: argon2id (argon2-cffi defaults), never stored or logged in clear; minimum 12 chars.
- Sign-in: one generic error for every failure (no user enumeration); a dummy hash is checked
  for unknown users so timing does not tell either. After `login_max_failures` failures the
  account locks for `login_lock_minutes`.
- MFA: TOTP (RFC 6238). Mandatory for admins: an admin account is created with a secret, and
  sign-in without a valid code fails. The secret is stored encrypted (app/secretbox.py).
- Sessions: 256-bit random bearer token, only its sha256 stored; absolute lifetime and idle
  timeout; revoked on logout, password change and deactivation.
- `must_change_password`: a fresh or reset account can only change its password until it does.
"""
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app import secretbox
from app.config import settings
from app.models import ROLES, User, UserSession

MIN_PASSWORD = 12
MFA_ROLES = {"admin"}
_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("timing-equaliser-not-a-password")


class AccountError(ValueError):
    """Message is safe to show to the user."""


def now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def check_password_policy(password: str, username: str = "") -> None:
    if len(password) < MIN_PASSWORD:
        raise AccountError(f"Password must be at least {MIN_PASSWORD} characters")
    if username and username.lower() in password.lower():
        raise AccountError("Password must not contain the username")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def _mfa_aad(user_id: int) -> bytes:
    return f"totp:{user_id}".encode()


def mfa_secret(user: User) -> str | None:
    return secretbox.decrypt_text(user.mfa_secret_enc, _mfa_aad(user.id)) if user.mfa_secret_enc else None


def set_new_mfa_secret(user: User) -> str:
    """Give the (flushed) user a fresh TOTP secret; returns the otpauth:// provisioning URI."""
    secret = pyotp.random_base32()
    user.mfa_secret_enc = secretbox.encrypt_text(secret, _mfa_aad(user.id))
    return pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="MedSeal")


def create_user(session: Session, *, username: str, role: str, password: str, full_name: str = "",
                hospital: str = "", must_change_password: bool = True) -> tuple[User, str | None]:
    """-> (user, otpauth URI or None). The caller commits."""
    username = username.strip().lower()
    if role not in ROLES:
        raise AccountError(f"Unknown role {role!r}")
    if not username or not username.replace(".", "").replace("_", "").replace("-", "").isalnum():
        raise AccountError("Username: letters, digits, '.', '_' or '-'")
    if role == "client" and not hospital.strip():
        raise AccountError("A client account needs its hospital")
    if session.scalar(select(User).where(User.username == username)) is not None:
        raise AccountError("Username is taken")
    check_password_policy(password, username)
    user = User(username=username, full_name=full_name.strip(), role=role, hospital=hospital.strip(),
                password_hash=hash_password(password), must_change_password=must_change_password,
                password_changed_at=now())
    session.add(user)
    session.flush()
    uri = set_new_mfa_secret(user) if role in MFA_ROLES else None
    return user, uri


@dataclass
class LoginResult:
    token: str
    user: User
    session: UserSession


def login(session: Session, username: str, password: str, totp: str | None, ip: str | None) -> LoginResult:
    user = session.scalar(select(User).where(User.username == (username or "").strip().lower()))
    generic = AccountError("Invalid username, password or code")
    if user is None:
        try:
            _hasher.verify(_DUMMY_HASH, password or "x")
        except VerificationError:
            pass
        raise generic
    if not user.active:
        raise generic
    locked = _aware(user.locked_until)
    if locked and locked > now():
        raise AccountError("Account is temporarily locked after failed sign-ins; try again later")
    try:
        _hasher.verify(user.password_hash, password or "")
        ok = True
    except (VerificationError, InvalidHashError):
        ok = False
    if ok and (user.role in MFA_ROLES or user.mfa_secret_enc):
        secret = mfa_secret(user)
        ok = bool(secret and totp and pyotp.TOTP(secret).verify(totp.strip(), valid_window=1))
    if not ok:
        user.failed_logins += 1
        if user.failed_logins >= settings.login_max_failures:
            user.locked_until = now() + timedelta(minutes=settings.login_lock_minutes)
            user.failed_logins = 0
        session.commit()
        raise generic
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_logins, user.locked_until = 0, None
    token = secrets.token_urlsafe(32)
    t = now()
    row = UserSession(user_id=user.id, token_hash=token_hash(token), created_at=t, last_seen_at=t,
                      expires_at=t + timedelta(hours=settings.session_hours), ip=ip)
    session.add(row)
    return LoginResult(token, user, row)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def resolve(session: Session, token: str) -> tuple[User, UserSession] | None:
    """The live session behind a bearer token, or None. Touches last_seen_at (idle timeout)."""
    row = session.scalar(select(UserSession).where(UserSession.token_hash == token_hash(token)))
    if row is None or row.revoked_at is not None:
        return None
    t = now()
    if _aware(row.expires_at) <= t or _aware(row.last_seen_at) + timedelta(minutes=settings.session_idle_minutes) <= t:
        return None
    user = session.get(User, row.user_id)
    if user is None or not user.active:
        return None
    if (t - _aware(row.last_seen_at)).total_seconds() > 60:  # no write on every single request
        row.last_seen_at = t
        session.commit()
    return user, row


def revoke_sessions(session: Session, user_id: int, except_id: int | None = None) -> None:
    q = update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_id is not None:
        q = q.where(UserSession.id != except_id)
    session.execute(q.values(revoked_at=now()))


def change_password(session: Session, user: User, current: str, new: str, keep_session_id: int) -> None:
    try:
        _hasher.verify(user.password_hash, current or "")
    except (VerificationError, InvalidHashError):
        raise AccountError("Current password is wrong") from None
    if current == new:
        raise AccountError("The new password must differ from the current one")
    check_password_policy(new, user.username)
    user.password_hash = hash_password(new)
    user.must_change_password = False
    user.password_changed_at = now()
    revoke_sessions(session, user.id, except_id=keep_session_id)


def public(user: User) -> dict:
    return {"id": user.id, "username": user.username, "full_name": user.full_name, "role": user.role,
            "hospital": user.hospital, "active": user.active, "mfa": bool(user.mfa_secret_enc),
            "must_change_password": user.must_change_password}

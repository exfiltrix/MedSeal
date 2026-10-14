"""Sign-in and user administration (app/accounts.py). Every step is audited by name."""
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import accounts, audit
from app.auth import _bearer, _session_user, require_admin
from app.db import get_session
from app.models import ROLES, User, iso_utc

router = APIRouter(tags=["accounts"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    totp: str | None = Field(default=None, max_length=10)


@router.post("/auth/login")
def login(body: LoginIn, request: Request, session: Session = Depends(get_session)):
    ip = audit.client_ip(request)
    try:
        result = accounts.login(session, body.username, body.password, body.totp, ip)
    except accounts.AccountError as e:
        audit.log(session, "login_failed", f"user:{body.username.strip().lower()[:64]}", ip=ip)
        session.commit()
        raise HTTPException(401, str(e)) from None
    audit.log(session, "login", f"user:{result.user.username}", ip=ip)
    session.commit()
    return {"token": result.token, "expires_at": iso_utc(result.session.expires_at), "user": accounts.public(result.user)}


def current(request: Request, authorization: str | None = Header(default=None),
            session: Session = Depends(get_session)):
    """The signed-in person (also while a password change is still pending)."""
    found = _session_user(session, request, _bearer(authorization), allow_password_change=True)
    if found is None:
        raise HTTPException(401, "Not signed in")
    return found


@router.get("/auth/me")
def me(found=Depends(current)):
    return accounts.public(found[0])


@router.post("/auth/logout")
def logout(request: Request, found=Depends(current), session: Session = Depends(get_session)):
    user, row = found
    row = session.merge(row)
    row.revoked_at = accounts.now()
    audit.log(session, "logout", f"user:{user.username}", ip=audit.client_ip(request))
    session.commit()
    return {"ok": True}


class PasswordIn(BaseModel):
    current: str = Field(min_length=1, max_length=256)
    new: str = Field(min_length=1, max_length=256)


@router.post("/auth/password")
def change_password(body: PasswordIn, request: Request, found=Depends(current), session: Session = Depends(get_session)):
    user, row = found
    user = session.merge(user)
    try:
        accounts.change_password(session, user, body.current, body.new, keep_session_id=row.id)
    except accounts.AccountError as e:
        raise HTTPException(422, str(e)) from None
    audit.log(session, "password_change", f"user:{user.username}", ip=audit.client_ip(request))
    session.commit()
    return accounts.public(user)


# --- administration -------------------------------------------------------------------------

class UserIn(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    role: str
    password: str = Field(min_length=1, max_length=256)  # temporary: changed at first sign-in
    full_name: str = Field(default="", max_length=200)
    hospital: str = Field(default="", max_length=300)


@router.get("/users")
def list_users(session: Session = Depends(get_session), _actor: str = Depends(require_admin)):
    return [accounts.public(u) for u in session.scalars(select(User).order_by(User.id))]


@router.post("/users", status_code=201)
def create_user(body: UserIn, request: Request, session: Session = Depends(get_session),
                actor: str = Depends(require_admin)):
    if body.role not in ROLES:
        raise HTTPException(422, f"role must be one of {', '.join(ROLES)}")
    try:
        user, uri = accounts.create_user(session, username=body.username, role=body.role, password=body.password,
                                         full_name=body.full_name, hospital=body.hospital)
    except accounts.AccountError as e:
        raise HTTPException(409 if "taken" in str(e) else 422, str(e)) from None
    audit.log(session, "user_create", actor, target=f"user:{user.username}", result=user.role,
              ip=audit.client_ip(request))
    session.commit()
    # The MFA enrolment URI is shown exactly once, to the admin creating the account.
    return accounts.public(user) | ({"mfa_provisioning_uri": uri} if uri else {})


def _target(session: Session, user_id: int) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(404, "User not found")
    return user


@router.post("/users/{user_id}/deactivate")
def deactivate(user_id: int, request: Request, session: Session = Depends(get_session),
               actor: str = Depends(require_admin)):
    user = _target(session, user_id)
    if actor == f"user:{user.username}":
        raise HTTPException(409, "An admin cannot deactivate their own account")
    user.active = False
    accounts.revoke_sessions(session, user.id)
    audit.log(session, "user_deactivate", actor, target=f"user:{user.username}", ip=audit.client_ip(request))
    session.commit()
    return accounts.public(user)


class ResetIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    reset_mfa: bool = False


@router.post("/users/{user_id}/reset")
def reset(user_id: int, body: ResetIn, request: Request, session: Session = Depends(get_session),
          actor: str = Depends(require_admin)):
    """New temporary password (changed at next sign-in), all sessions revoked, lock lifted;
    optionally a new MFA secret (lost phone) — its URI is returned once."""
    user = _target(session, user_id)
    try:
        accounts.check_password_policy(body.password, user.username)
    except accounts.AccountError as e:
        raise HTTPException(422, str(e)) from None
    user.password_hash = accounts.hash_password(body.password)
    user.must_change_password = True
    user.failed_logins, user.locked_until = 0, None
    accounts.revoke_sessions(session, user.id)
    uri = accounts.set_new_mfa_secret(user) if body.reset_mfa else None
    audit.log(session, "user_reset", actor, target=f"user:{user.username}",
              result="password+mfa" if uri else "password", ip=audit.client_ip(request))
    session.commit()
    return accounts.public(user) | ({"mfa_provisioning_uri": uri} if uri else {})

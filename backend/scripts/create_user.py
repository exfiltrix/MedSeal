"""Create a personal account from the server's shell — how the first admin comes to exist.

    .venv/bin/python -m scripts.create_user --username alice --role admin --full-name "Alice K."

The password is asked for interactively (never on the command line, where it would land in the
shell history and the process list) and must be changed at first sign-in. For an admin the TOTP
enrolment URI is printed once: scan it with an authenticator app before closing the terminal.
"""
import argparse
import getpass
import sys

from app import accounts, audit
from app.db import SessionLocal, init_engine
from app.models import ROLES


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--username", required=True)
    ap.add_argument("--role", required=True, choices=ROLES)
    ap.add_argument("--full-name", default="")
    ap.add_argument("--hospital", default="", help="required for role=client")
    args = ap.parse_args(argv)

    password = getpass.getpass("Temporary password (min 12 chars): ")
    if password != getpass.getpass("Repeat: "):
        print("Passwords differ", file=sys.stderr)
        return 2
    init_engine()
    with SessionLocal() as session:
        try:
            user, uri = accounts.create_user(session, username=args.username, role=args.role, password=password,
                                             full_name=args.full_name, hospital=args.hospital)
        except accounts.AccountError as e:
            print(e, file=sys.stderr)
            return 2
        audit.log(session, "user_create", "cli", target=f"user:{user.username}", result=user.role, ip="local")
        session.commit()
    print(f"created {user.username} ({user.role}); the password must be changed at first sign-in")
    if uri:
        print("MFA enrolment (scan now, shown once):\n" + uri)
    return 0


if __name__ == "__main__":
    sys.exit(main())

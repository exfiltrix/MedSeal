"""Encrypt patient data stored before encryption at rest: sealed image files and inbox results.

    .venv/bin/python -m scripts.encrypt_storage      # MEDSEAL_DATA_KEY must be the production key

Idempotent: already-encrypted files and rows are skipped, so it can be re-run after an
interruption. Back up the storage directory and the database first.
"""
import sys

from sqlalchemy import select

from app import storage
from app.automation import inbox
from app.db import SessionLocal, init_engine
from app.models import InboxItem, Seal


def main() -> int:
    init_engine()
    files = rows = 0
    with SessionLocal() as session:
        for seal in session.scalars(select(Seal)):
            if (storage.settings.storage_dir / seal.file_name).exists() and storage.encrypt_in_place(seal.file_name):
                files += 1
        for item in session.scalars(select(InboxItem)):
            if item.result_json and not item.result_json.startswith(inbox.ENC_PREFIX):
                inbox.store_result(item, inbox.load_result(item))
                rows += 1
        session.commit()
    print(f"encrypted {files} sealed file(s) and {rows} inbox result(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

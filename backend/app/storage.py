"""Sealed image files at rest (patient data): AES-256-GCM via app/secretbox.py.

Each file is bound to its own name (aad b"sealed-file:<name>"), so files cannot be swapped on disk
without failing to decrypt. Files written before encryption are still read (development / an
in-place migration with scripts/encrypt_storage.py); new ones are always encrypted.
"""
from app import secretbox
from app.config import settings


def _aad(file_name: str) -> bytes:
    return f"sealed-file:{file_name}".encode()


def write_sealed(file_name: str, content: bytes) -> None:
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    (settings.storage_dir / file_name).write_bytes(secretbox.encrypt(content, _aad(file_name)))


def read_sealed(file_name: str) -> bytes | None:
    path = settings.storage_dir / file_name
    if not path.exists():
        return None
    blob = path.read_bytes()
    return secretbox.decrypt(blob, _aad(file_name)) if secretbox.is_encrypted(blob) else blob


def encrypt_in_place(file_name: str) -> bool:
    """-> True if the file was plaintext and is now encrypted."""
    path = settings.storage_dir / file_name
    blob = path.read_bytes()
    if secretbox.is_encrypted(blob):
        return False
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(secretbox.encrypt(blob, _aad(file_name)))
    tmp.replace(path)
    return True

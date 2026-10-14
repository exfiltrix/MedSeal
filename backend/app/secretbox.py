"""Encryption at rest for the secrets and patient data MedSeal keeps (AES-256-GCM).

One data key (MEDSEAL_DATA_KEY: 32 random bytes, base64) encrypts:
  - TOTP secrets of user accounts,
  - private signing keys on disk (app/seal/keys.py),
  - sealed image files and stored previews (patient data).

Format: b"MSB1" + 12-byte nonce + ciphertext+tag. `aad` binds a ciphertext to its purpose
(e.g. b"device-key:3"), so a blob copied to another slot fails to decrypt instead of being used.

Production: the key comes from the environment (injected by the KMS/secret manager, never in a
file next to the data); app/hardening.py refuses to start without it. Development: generated once
into keys_dir/data.key (0600) so a laptop works with no setup.

Losing the data key = losing the encrypted data: back it up with the same care as the root key.
"""
import base64
import os
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

MAGIC = b"MSB1"


class SecretBoxError(ValueError):
    pass


def _dev_key_path():
    return settings.keys_dir / "data.key"


@lru_cache(maxsize=4)
def _key(env_value: str, dev_path: str) -> bytes:
    if env_value:
        key = base64.b64decode(env_value)
    else:
        path = settings.keys_dir / "data.key"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(base64.b64encode(AESGCM.generate_key(bit_length=256)))
        key = base64.b64decode(path.read_bytes())
    if len(key) != 32:
        raise SecretBoxError("MEDSEAL_DATA_KEY must be 32 bytes, base64-encoded")
    return key


def data_key() -> bytes:
    return _key(settings.data_key, str(_dev_key_path()))


def new_key_b64() -> str:
    return base64.b64encode(AESGCM.generate_key(bit_length=256)).decode()


def encrypt(plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return MAGIC + nonce + AESGCM(data_key()).encrypt(nonce, plaintext, aad)


def is_encrypted(blob: bytes) -> bool:
    return blob[:4] == MAGIC


def decrypt(blob: bytes, aad: bytes) -> bytes:
    if not is_encrypted(blob):
        raise SecretBoxError("not a MedSeal encrypted blob")
    try:
        return AESGCM(data_key()).decrypt(blob[4:16], blob[16:], aad)
    except Exception as e:  # InvalidTag: wrong key, wrong slot, or tampered
        raise SecretBoxError("cannot decrypt: wrong key, wrong purpose or tampered data") from e


def encrypt_text(text: str, aad: bytes) -> str:
    return base64.b64encode(encrypt(text.encode(), aad)).decode()


def decrypt_text(token: str, aad: bytes) -> str:
    return decrypt(base64.b64decode(token), aad).decode()

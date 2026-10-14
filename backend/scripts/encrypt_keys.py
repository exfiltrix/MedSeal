"""Encrypt private key files written before keys were encrypted at rest (app/seal/keys.py).

    .venv/bin/python -m scripts.encrypt_keys          # MEDSEAL_DATA_KEY must be the production key

Each plaintext device_<id>.pem / root.pem is re-written as an AES-256-GCM blob bound to its slot,
atomically (temp file + rename), and read back before moving on. Already-encrypted files are left
alone, so running it twice is harmless. Back up the keys directory first.
"""
import sys

from app.seal import keys


def main() -> int:
    files = keys.plaintext_key_files()
    for path in files:
        if path == keys.settings.root_key_path:
            aad = b"root-key"
        else:
            aad = f"device-key:{path.stem.removeprefix('device_')}".encode()
        key = keys._read_private(path, aad)
        keys._write_private(path, key, aad)
        assert keys.public_key_hex(keys._read_private(path, aad).public_key()) == keys.public_key_hex(key.public_key())
        print(f"encrypted {path.name}")
    print(f"done: {len(files)} file(s) encrypted, {len(keys.plaintext_key_files())} plaintext left")
    return 0


if __name__ == "__main__":
    sys.exit(main())

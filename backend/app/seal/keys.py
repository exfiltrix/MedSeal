"""Gateway and root key material.

Private keys are read and written only here and used only by the signing modules.
They are never logged, never returned by the API and never leave this module except
as a signer object (anything with .sign(message) -> signature).

Two backends (MEDSEAL_KEY_BACKEND):
- "file" (default): Ed25519 keys on disk, **encrypted at rest** with the data key
  (app/secretbox.py, AES-256-GCM, each file bound to its slot: b"device-key:<id>", b"root-key").
  Plaintext PEM files from before this change are still read in development; production refuses
  to start while any exist (scripts/encrypt_keys.py converts them).
- "pkcs11": keys are generated inside an HSM and never leave it; signing happens in the HSM
  (CKM_EDDSA). MEDSEAL_PKCS11_LIB (the vendor's module), MEDSEAL_PKCS11_TOKEN (label),
  MEDSEAL_PKCS11_PIN. Signatures are plain Ed25519: verifiers and the seal format do not change.

The root public key is always also written to MEDSEAL_ROOT_PUBKEY_PATH: verifiers need only it.
"""
import json
import os
import threading
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app import secretbox
from app.config import settings
from app.models import Device, iso_utc


CERT_PREFIX = b"MEDSEAL-DEVICE-v1\n"
ED25519_OID = "1.3.101.112"


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _key_path(device_id: int) -> Path:
    return settings.keys_dir / f"device_{device_id}.pem"


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def _write_private(path: Path, key: Ed25519PrivateKey, aad: bytes) -> None:
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    _atomic_write(path, secretbox.encrypt(pem, aad), 0o600)


def _read_private(path: Path, aad: bytes) -> Ed25519PrivateKey:
    blob = path.read_bytes()
    pem = secretbox.decrypt(blob, aad) if secretbox.is_encrypted(blob) else blob  # legacy plaintext: dev only
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path.name} is not an Ed25519 key")
    return key


def _write_public(path: Path, key: Ed25519PublicKey) -> None:
    pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    _atomic_write(path, pem, 0o644)


def plaintext_key_files() -> list[Path]:
    """Private key files still stored unencrypted (production refuses to start while any exist)."""
    if not settings.keys_dir.exists():
        return []
    candidates = list(settings.keys_dir.glob("device_*.pem")) + [settings.root_key_path]
    return [p for p in candidates if p.exists() and not secretbox.is_encrypted(p.read_bytes())]


# --- PKCS#11 (HSM) ---------------------------------------------------------------------------

_hsm_lock = threading.Lock()  # one PKCS#11 session, used from several request threads


@lru_cache(maxsize=1)
def _hsm_session():
    import pkcs11

    lib = pkcs11.lib(settings.pkcs11_lib)
    token = lib.get_token(token_label=settings.pkcs11_token)
    return token.open(user_pin=settings.pkcs11_pin, rw=True)


class HsmSigner:
    """An Ed25519 private key inside the HSM, addressed by its label. The key never leaves it."""

    def __init__(self, label: str):
        self.label = label

    def _key(self, object_class):
        from pkcs11 import KeyType

        return _hsm_session().get_key(object_class=object_class, key_type=KeyType.EC_EDWARDS, label=self.label)

    def sign(self, message: bytes) -> bytes:
        from pkcs11 import Mechanism, ObjectClass

        with _hsm_lock:
            return self._key(ObjectClass.PRIVATE_KEY).sign(message, mechanism=Mechanism.EDDSA)

    def public_key(self) -> Ed25519PublicKey:
        from pkcs11 import Attribute, ObjectClass

        with _hsm_lock:
            point = bytes(self._key(ObjectClass.PUBLIC_KEY)[Attribute.EC_POINT])
        raw = point[2:] if len(point) == 34 and point[0] == 0x04 else point  # DER OCTET STRING wrapper
        return Ed25519PublicKey.from_public_bytes(raw)


def _hsm_has(label: str) -> bool:
    from pkcs11 import KeyType, ObjectClass

    with _hsm_lock:
        return any(True for _ in _hsm_session().get_objects(
            {pkcs11_attr("CLASS"): ObjectClass.PRIVATE_KEY, pkcs11_attr("KEY_TYPE"): KeyType.EC_EDWARDS,
             pkcs11_attr("LABEL"): label}))


def pkcs11_attr(name: str):
    from pkcs11 import Attribute

    return getattr(Attribute, name)


def _hsm_generate(label: str) -> HsmSigner:
    from pkcs11 import Attribute, KeyType
    from pkcs11.util.ec import encode_named_curve_parameters

    # Labels address keys, so they must stay unique: a second key under the same label would make
    # every later signature ambiguous. Never overwrite or delete inside the HSM from here.
    if _hsm_has(label):
        raise FileExistsError(f"the HSM already holds a key labelled {label!r} (a reused database? an old "
                              "trust root?): retire it with the HSM's own tools before creating a new one")
    with _hsm_lock:
        params = _hsm_session().create_domain_parameters(
            KeyType.EC_EDWARDS, {Attribute.EC_PARAMS: encode_named_curve_parameters(ED25519_OID)}, local=True)
        # sensitive + non-extractable: the private key can sign but can never be read out of the HSM
        params.generate_keypair(store=True, label=label,
                                private_template={Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False})
    return HsmSigner(label)


def _hsm() -> bool:
    return settings.key_backend == "pkcs11"


def _device_label(device_id: int) -> str:
    return f"medseal-device-{device_id}"


ROOT_LABEL = "medseal-root"


# --- public interface ------------------------------------------------------------------------

def create_device_key(device_id: int) -> str:
    """Generate and store a device key pair. Returns only the public key (hex)."""
    if _hsm():
        return public_key_hex(_hsm_generate(_device_label(device_id)).public_key())
    key = Ed25519PrivateKey.generate()
    _write_private(_key_path(device_id), key, f"device-key:{device_id}".encode())
    return public_key_hex(key.public_key())


def load_private_key(device_id: int):
    """The device's signer: .sign(message) -> Ed25519 signature."""
    if _hsm():
        return HsmSigner(_device_label(device_id))
    path = _key_path(device_id)
    if not path.exists():
        raise KeyError(f"no private key for device {device_id}")
    return _read_private(path, f"device-key:{device_id}".encode())


def public_key_hex(pub: Ed25519PublicKey) -> str:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def root_key_exists() -> bool:
    if _hsm():
        return settings.root_pubkey_path.exists()
    return settings.root_key_path.exists() and settings.root_pubkey_path.exists()


def ensure_root_key() -> None:
    """Create the local demo root key once, without ever replacing an existing trust root."""
    if not root_key_exists():
        create_root_key()


def create_root_key(force: bool = False) -> None:
    """Create the trust root; refuse an implicit overwrite by default."""
    private_path, public_path = settings.root_key_path, settings.root_pubkey_path
    if not force and (public_path.exists() or (not _hsm() and private_path.exists())):
        raise FileExistsError("root key already exists; refusing to overwrite the trust root")
    if _hsm():
        if _hsm_has(ROOT_LABEL) and not force:
            # The trust root already lives in the HSM and only root.pub was missing: re-export it.
            _write_public(public_path, HsmSigner(ROOT_LABEL).public_key())
            return
        _write_public(public_path, _hsm_generate(ROOT_LABEL).public_key())
        return
    key = Ed25519PrivateKey.generate()
    _write_private(private_path, key, b"root-key")
    _write_public(public_path, key.public_key())


def load_root_private_key():
    if _hsm():
        return HsmSigner(ROOT_LABEL)
    if not settings.root_key_path.exists():
        raise KeyError("root key is not configured; run python -m scripts.create_root_key")
    return _read_private(settings.root_key_path, b"root-key")


def load_root_public_key() -> Ed25519PublicKey:
    if not settings.root_pubkey_path.exists():
        raise KeyError("root public key is not configured")
    key = serialization.load_pem_public_key(settings.root_pubkey_path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("root public key is not Ed25519")
    return key


def sign_root(message: bytes) -> bytes:
    return load_root_private_key().sign(message)


def verify_root(signature: bytes, message: bytes) -> bool:
    try:
        load_root_public_key().verify(signature, message)
    except Exception:
        return False
    return True


def device_certificate_message(device: Device) -> bytes:
    return CERT_PREFIX + canonical_json(
        {
            "device_id": device.id,
            "name": device.name,
            "hospital": device.hospital,
            "public_key_hex": device.public_key_hex,
            "created_at": iso_utc(device.created_at),
        }
    )


def certify_device(device: Device) -> str:
    signature = sign_root(device_certificate_message(device))
    device.cert_sig_hex = signature.hex()
    return device.cert_sig_hex


def device_certificate_valid(device: Device) -> bool:
    if not device.cert_sig_hex:
        return False
    try:
        signature = bytes.fromhex(device.cert_sig_hex)
    except ValueError:
        return False
    return verify_root(signature, device_certificate_message(device))

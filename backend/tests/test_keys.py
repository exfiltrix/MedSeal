"""Signing keys at rest (app/seal/keys.py): encrypted files, legacy migration, and an HSM over PKCS#11.

The HSM tests run against SoftHSM2 when it is installed (brew install softhsm / apt install softhsm2)
and are skipped otherwise.
"""
import os
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import secretbox
from app.config import settings
from app.seal import keys
from tests.conftest import admin_headers, xray_png

SOFTHSM_LIB = os.environ.get("MEDSEAL_TEST_PKCS11_LIB") or next(
    (p for p in ("/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/lib/softhsm/libsofthsm2.so",
                 "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so") if os.path.exists(p)), "")


def test_a_key_file_cannot_be_moved_to_another_slot(client, device, tmp_path):
    """Each file is bound to its slot: device 1's key copied over the root key does not decrypt."""
    blob = (tmp_path / "keys" / f"device_{device['id']}.pem").read_bytes()
    with pytest.raises(secretbox.SecretBoxError):
        secretbox.decrypt(blob, b"root-key")


def test_legacy_plaintext_keys_are_encrypted_in_place(client, device, tmp_path):
    from scripts import encrypt_keys

    path = tmp_path / "keys" / f"device_{device['id']}.pem"
    before = keys.public_key_hex(keys.load_private_key(device["id"]).public_key())
    path.write_bytes(keys.load_private_key(device["id"]).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    assert path in keys.plaintext_key_files()
    assert encrypt_keys.main() == 0
    assert keys.plaintext_key_files() == [] and path.read_bytes().startswith(b"MSB1")
    assert keys.public_key_hex(keys.load_private_key(device["id"]).public_key()) == before
    r = client.post("/api/seal", files={"file": ("x.png", xray_png(seed=600))}, headers=device["auth"])
    assert r.status_code == 200  # the same key still signs


@pytest.fixture(scope="module")
def softhsm_token(tmp_path_factory):
    """One SoftHSM token per test module: the PKCS#11 library reads its configuration once per process."""
    if not SOFTHSM_LIB or not shutil.which("softhsm2-util"):
        pytest.skip("SoftHSM2 is not installed")
    root = tmp_path_factory.mktemp("softhsm")
    (root / "tokens").mkdir()
    conf = root / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {root / 'tokens'}\nobjectstore.backend = file\nlog.level = ERROR\n")
    os.environ["SOFTHSM2_CONF"] = str(conf)
    subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "medseal-test", "--pin", "123456",
                    "--so-pin", "654321"], check=True, capture_output=True)
    return conf


@pytest.fixture
def hsm(softhsm_token, monkeypatch):
    for name, value in {"key_backend": "pkcs11", "pkcs11_lib": SOFTHSM_LIB, "pkcs11_token": "medseal-test",
                        "pkcs11_pin": "123456"}.items():
        monkeypatch.setattr(settings, name, value)
    yield


def test_hsm_keys_seal_and_verify_and_never_touch_the_disk(hsm, client, tmp_path):
    r = client.post("/api/devices", json={"name": "HSM-01", "hospital": "Namangan"}, headers=admin_headers())
    assert r.status_code == 201, r.text
    auth = {"Authorization": f"Bearer {r.json()['token']}"}
    body = client.post("/api/seal", files={"file": ("x.png", xray_png(seed=610))}, headers=auth).json()
    sealed = client.get(body["download_url"], headers=auth).content
    assert client.post("/api/verify", files={"file": ("x.png", sealed)}).json()["status"] == "authentic"
    assert client.get("/api/ledger/check").json()["ok"] is True  # anchors signed by the HSM root
    assert not list((tmp_path / "keys").glob("device_*.pem"))  # no private key file at all
    assert not settings.root_key_path.exists() and settings.root_pubkey_path.exists()


def test_hsm_private_keys_are_not_extractable(hsm, client):
    """Also: root.pub lost while the root key is still in the HSM -> re-exported, never regenerated."""
    from pkcs11 import Attribute, KeyType, ObjectClass

    assert not settings.root_pubkey_path.exists()  # fresh test dirs, same HSM token as the test above
    keys.ensure_root_key()
    assert settings.root_pubkey_path.exists()
    key = keys._hsm_session().get_key(object_class=ObjectClass.PRIVATE_KEY, key_type=KeyType.EC_EDWARDS,
                                      label=keys.ROOT_LABEL)
    assert key[Attribute.SENSITIVE] is True and key[Attribute.EXTRACTABLE] is False
    assert isinstance(keys.load_root_private_key(), keys.HsmSigner)
    assert not isinstance(keys.load_root_private_key(), Ed25519PrivateKey)


def test_hsm_refuses_a_second_key_under_the_same_label(hsm, client):
    """A reused database restarts device ids at 1: the HSM must not end up with two device-1 keys."""
    if not keys._hsm_has(keys._device_label(1)):
        keys.create_device_key(1)
    with pytest.raises(FileExistsError, match="already holds"):
        keys.create_device_key(1)

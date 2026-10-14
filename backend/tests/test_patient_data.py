"""Patient data at rest (app/storage.py, automation.inbox): encrypted, bound to its slot, and
image previews removed after the retention period while verdicts stay."""
from datetime import timedelta

import pytest
from sqlalchemy import update

from app import db, secretbox, storage
from app.automation import inbox
from app.config import settings
from app.models import InboxItem, Seal
from tests.conftest import doctor_headers, xray_png


def _seal(client, device, seed):
    body = client.post("/api/seal", files={"file": ("x.png", xray_png(seed=seed))}, headers=device["auth"]).json()
    return body, client.get(body["download_url"], headers=device["auth"]).content


def test_sealed_files_are_encrypted_and_still_served(client, device, tmp_path):
    body, downloaded = _seal(client, device, 700)
    with db.SessionLocal() as s:
        name = s.get(Seal, body["seal_id"]).file_name
    on_disk = (tmp_path / "storage" / name).read_bytes()
    assert on_disk.startswith(b"MSB1") and b"medseal_uid" not in on_disk  # nothing readable on disk
    assert downloaded.startswith(b"\x89PNG")  # the API hands back the real file
    assert client.post("/api/verify", files={"file": ("x.png", downloaded)}).json()["status"] == "authentic"


def test_a_sealed_file_cannot_be_swapped_on_disk(client, device, tmp_path):
    a, _ = _seal(client, device, 701)
    b, _ = _seal(client, device, 702)
    with db.SessionLocal() as s:
        name_a, name_b = s.get(Seal, a["seal_id"]).file_name, s.get(Seal, b["seal_id"]).file_name
    (tmp_path / "storage" / name_a).write_bytes((tmp_path / "storage" / name_b).read_bytes())
    with pytest.raises(secretbox.SecretBoxError):
        storage.read_sealed(name_a)


def _inbox_item(client):
    r = client.post("/api/inbox", files=[("files", ("scan.png", xray_png(seed=710)))], headers=doctor_headers())
    assert r.status_code == 200, r.text
    return r.json()[0]["id"]


def test_inbox_results_are_encrypted_in_the_database(client):
    item_id = _inbox_item(client)
    with db.SessionLocal() as s:
        raw = s.get(InboxItem, item_id).result_json
    assert raw.startswith(inbox.ENC_PREFIX) and "preview_png" not in raw
    detail = client.get(f"/api/inbox/{item_id}", headers=doctor_headers()).json()
    assert detail["result"]["preview_png"]  # the doctor still sees the preview


def test_previews_expire_but_verdicts_stay(client):
    item_id = _inbox_item(client)
    with db.SessionLocal() as s:
        s.execute(update(InboxItem).where(InboxItem.id == item_id)
                  .values(received_at=inbox.utcnow() - timedelta(days=31)))
        s.commit()
        assert inbox.purge_previews(s, 30) == 1
        assert inbox.purge_previews(s, 30) == 0  # once only
    detail = client.get(f"/api/inbox/{item_id}", headers=doctor_headers()).json()
    assert "preview_png" not in detail["result"]
    assert detail["status"] == "unsigned" and detail["severity"] == "warning"  # the record stays
    pdf = client.get(f"/api/inbox/{item_id}/pdf", headers=doctor_headers())
    assert pdf.status_code == 200  # the report still renders without the image


def test_retention_is_off_without_a_period(client):
    _inbox_item(client)
    with db.SessionLocal() as s:
        assert inbox.purge_previews(s, settings.inbox_preview_days) == 0


def test_old_plaintext_data_is_encrypted_by_the_migration_script(client, device, tmp_path):
    from scripts import encrypt_storage

    body, _ = _seal(client, device, 720)
    item_id = _inbox_item(client)
    with db.SessionLocal() as s:
        seal_row, item = s.get(Seal, body["seal_id"]), s.get(InboxItem, item_id)
        path = tmp_path / "storage" / seal_row.file_name
        path.write_bytes(storage.read_sealed(seal_row.file_name))  # as written before encryption
        item.result_json = '{"status": "unsigned", "preview_png": "AAAA"}'
        s.commit()
    assert encrypt_storage.main() == 0
    assert path.read_bytes().startswith(b"MSB1")
    with db.SessionLocal() as s:
        assert s.get(InboxItem, item_id).result_json.startswith(inbox.ENC_PREFIX)
    assert encrypt_storage.main() == 0  # idempotent

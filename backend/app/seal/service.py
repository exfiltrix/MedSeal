"""Gateway: seal an uploaded image and record it in the ledger."""
import json
import time
import uuid

from sqlalchemy.orm import Session

from app.imaging import (
    META_VERSION,
    LoadedImage,
    assign_uid,
    dhash,
    load_image,
    meta_fields,
    meta_hash,
    patient_reference,
    sealed_file_bytes,
    to_grayscale,
)
from app.models import Device, Seal, utcnow
from app import storage
from app.seal import anchors, core, keys, ledger, recovery, signing


class SealError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def seal_upload(session: Session, image: LoadedImage, device_id: int) -> tuple[Seal, float]:
    """Returns (ledger row, sealing time in ms). Re-sealing identical pixels returns the existing row."""
    device = session.get(Device, device_id)
    if device is None:
        raise SealError(404, "Device not found")
    if device.revoked:
        raise SealError(409, "Device is revoked")

    existing = ledger.find_by_uid(session, image.uid) if image.uid else None
    if existing is not None:
        if core.changed_tiles(image.px, ledger.to_record(existing)):
            raise SealError(409, f"Image {image.uid} is already sealed with different pixels (seal {existing.id})")
        return existing, 0.0

    # Search whenever the supplied ID is absent or unknown. An attacker must not bypass the
    # content guard by attaching a fresh random UID to an edited derivative.
    if image.uid is None or existing is None:
        shape_json = json.dumps(list(image.px.shape))
        match = recovery.find_content_match(session, image.px, shape_json, str(image.px.dtype))
        if match:
            candidate, fraction = match
            if fraction >= 1.0:
                return candidate, 0.0
            raise SealError(409, f"Image is derived from sealed image #{candidate.id}")

    uid = assign_uid(image)
    content, ext = sealed_file_bytes(image)
    # Sign the metadata of the file actually handed back (see sealed_file_bytes), so the sealed
    # copy verifies as authentic and a display chunk added later shows up as metadata_changed.
    fields = meta_fields(load_image(content), version=META_VERSION)
    mh = meta_hash(fields)
    created_at = utcnow()
    patient_ref = patient_reference(image.patient_id)
    key = keys.load_private_key(device.id)

    t0 = time.perf_counter()
    tile = core.tile_size_for(image.px.shape)
    leaves = core.tile_hashes(image.px, uid, tile)
    root = core.merkle_root(leaves)
    signature = signing.sign_v2(
        key,
        uid=uid,
        device_id=device.id,
        created_at=created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        shape=json.dumps(list(image.px.shape)),
        dtype=str(image.px.dtype),
        tile=tile,
        root_hex=root.hex(),
        meta_hash_hex=mh.hex(),
        meta_version=META_VERSION,
        patient_ref=patient_ref,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000
    record = {"uid": uid, "tile": tile, "leaves": leaves, "root": root, "sig": signature}

    file_name = f"{uuid.uuid4().hex}.{ext}"
    storage.write_sealed(file_name, content)  # encrypted at rest (patient data)

    row = Seal(
        uid=uid,
        device_id=device.id,
        created_at=created_at,
        shape=json.dumps(list(image.px.shape)),
        dtype=str(image.px.dtype),
        tile=record["tile"],
        leaves_json=ledger.leaves_to_json(record["leaves"]),
        root_hex=record["root"].hex(),
        meta_hash_hex=mh.hex(),
        meta_json=json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        meta_version=META_VERSION,
        sig_version=2,
        patient_ref=patient_ref,
        phi_warning="burned_in_annotation" if image.burned_in_annotation else "",
        dhash_hex=dhash(to_grayscale(image.px)),
        sig_hex=record["sig"].hex(),
        file_name=file_name,
    )
    ledger.append(session, row)
    session.commit()
    anchors.append_anchor(row)
    return row, elapsed_ms

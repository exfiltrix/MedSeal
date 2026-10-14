"""Calibrate the AI shield threshold and measure how well it works.

    .venv/bin/python -m scripts.calibrate_shield          # needs data/nih (python -m scripts.fetch_dataset)

Clean adult X-rays from data/nih (same domain as the demo images) are split in two halves:
  - calibration half: threshold = 99th percentile of the squeeze distance;
  - held-out half: false positive rate on clean images, and detection rate on images
    attacked with FGSM/PGD (only attacks that actually flipped the diagnosis count).
Everything goes to app/ai/shield_calibration.json (commit it; the passport reads the numbers).
"""
import argparse
import json
from datetime import datetime, timezone

import numpy as np
import torch

from app.ai import attacks, model, shield
from app.ai.statistics import clopper_pearson
from app.config import settings
from app.imaging import display_pixels, load_image

PERCENTILE = 99
EPS = [0.5, 1, 2, 4]
BATCH = 8


def load_inputs(paths) -> list[np.ndarray]:
    return [model.model_input(display_pixels(load_image(p.read_bytes()))) for p in paths]


@torch.no_grad()
def raw(imgs: list[np.ndarray], squeezers) -> np.ndarray:
    """[n, len(squeezers)] squeeze distances, before any calibration exists."""
    return np.concatenate([
        shield.raw_distances(torch.cat([model.preprocess(v) for v in imgs[i:i + BATCH]]), squeezers).numpy()
        for i in range(0, len(imgs), BATCH)
    ])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-attack", type=int, default=30, help="held-out healthy images to attack")
    ap.add_argument("--squeezers", default=",".join(shield.SQUEEZERS),
                    help="comma-separated; 'median3' alone reproduces the v1 shield")
    args = ap.parse_args()
    squeezers = args.squeezers.split(",")

    nih = settings.data_dir / "nih"
    files = sorted((nih / "normal").glob("*.png")) + sorted((nih / "findings").glob("*.png"))
    if not files:
        raise SystemExit(f"No images in {nih}. Run: python -m scripts.fetch_dataset")
    calib, held = files[0::2], files[1::2]

    r_calib = raw(load_inputs(calib), squeezers)
    # Each squeezer's distance has its own scale; normalise by its median on clean images so the
    # max over squeezers is not just "whichever squeezer has the biggest numbers".
    scales = {k: round(float(np.median(r_calib[:, i])), 4) for i, k in enumerate(squeezers)}
    scale_vec = np.array([scales[k] for k in squeezers])

    def score(imgs):
        return (raw(imgs, squeezers) / scale_vec).max(axis=1)

    threshold = round(float(np.percentile((r_calib / scale_vec).max(axis=1), PERCENTILE)), 3)
    held_imgs = load_inputs(held)
    fpr = float((score(held_imgs) > threshold).mean())
    print(f"threshold {threshold} ({PERCENTILE}th pct of {len(calib)} clean), held-out FPR {fpr:.1%} on {len(held)}")

    idx = model.pathology_index()
    preds = [model.predict(img)[model.DEMO_PATHOLOGY] for img in held_imgs]
    healthy = [img for img, p, v in zip(held_imgs, held, preds) if "normal" in p.parent.name and v < model.THRESHOLD]
    # Review round 1: the shield was only ever measured on healthy -> sick attacks. Hiding a finding
    # (sick -> healthy) turned out to be far harder for it, so both directions are measured.
    sick = [img for img, v in zip(held_imgs, preds) if v >= model.THRESHOLD]

    def measure(imgs: list[np.ndarray], to_sick: bool) -> dict:
        x = torch.cat([model.preprocess(img) for img in imgs[: args.n_attack]])
        out = {}
        for method, attack in attacks.ATTACKS.items():
            out[method] = {}
            for eps in EPS:
                adv = [model.to_uint8(attack(x[i:i + 1], eps)) for i in range(len(x))]  # uint8: as uploaded
                with torch.no_grad():
                    s = model.scores(torch.cat([model.preprocess(a) for a in adv]))[:, idx]
                fooled = [a for a, v in zip(adv, s) if (v > model.THRESHOLD if to_sick else v < model.THRESHOLD)]
                rate = round(float((score(fooled) > threshold).mean()), 3) if fooled else None
                out[method][f"{eps:g}"] = {
                    "attacks_that_fooled_model": len(fooled),
                    "detected_count": round(rate * len(fooled)) if rate is not None else 0,
                    "detected": rate,
                }
                print(f"{'H->S' if to_sick else 'S->H'} {method} eps={eps:g}: fooled {len(fooled)}/{len(x)}, "
                      f"detected {rate if rate is None else f'{rate:.0%}'}", flush=True)
        return out

    detection = measure(healthy, to_sick=True)
    detection_reverse = measure(sick, to_sick=False) if sick else None
    previous = {}
    if settings.shield_calibration.exists():
        previous = json.loads(settings.shield_calibration.read_text())
    payload = {
        "method": "max over squeezers (" + ", ".join(squeezers) + ") of the L1 distance of DenseNet logits, "
                  "each divided by its median on clean X-rays",
        "version": 2,
        "squeezers": squeezers,
        "scales": scales,
        "threshold": threshold,
        "percentile": PERCENTILE,
        "dataset": "NIH ChestX-ray14 (CC0), 300 px subset: No Finding + findings",
        "n_calibration": len(calib),
        "n_held_out": len(held),
        "false_positive_count": round(fpr * len(held)),
        "false_positive_rate": round(fpr, 3),
        "detection_rate": detection,
        "detection_rate_reverse": detection_reverse,  # sick -> healthy: hiding a finding
        "confidence_intervals": {
            "detection_pgd_eps1": list(clopper_pearson(
                detection["pgd"]["1"]["detected_count"], detection["pgd"]["1"]["attacks_that_fooled_model"]
            )),
            "false_positive_rate": list(clopper_pearson(round(fpr * len(held)), len(held))),
        },
        "adaptive_attack_tested": False,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    # An adaptive result belongs to the shield it was measured against: never carry it over to a new one.
    if "adaptive" in previous and previous.get("squeezers") == squeezers and previous.get("threshold") == threshold:
        payload["adaptive"] = previous["adaptive"]
        payload["adaptive_attack_tested"] = True
    settings.shield_calibration.write_text(json.dumps(payload, indent=2) + "\n")
    print("saved", settings.shield_calibration)


if __name__ == "__main__":
    main()

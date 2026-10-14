"""Adaptive attack on the AI shield (AI-03): an attacker who knows the shield and optimises against it.

    .venv/bin/python -m scripts.adaptive_attack            # after scripts.calibrate_shield; ~15 min on CPU

The standard crash-test attacks (FGSM/PGD) only try to flip the diagnosis; the shield was
calibrated against exactly those. Here the attacker minimises, at the same time,

    flip loss   push the Pneumonia score across 0.5 (with a small margin)
    shield loss keep the shield score below its threshold (exact gradients: the shield's
                squeezers are torch code, see app/ai/shield.py)

inside the same L-inf eps-ball, then rounds to 8 bits as a real uploaded PNG would be, and is
scored by the real shield. Both directions are attacked: healthy -> sick and sick -> healthy
(hiding a finding is the more dangerous one). Held-out NIH images (the half calibration did not use).

Writes the result to shield_calibration.json under "adaptive" (commit it): the passport shows it
and adds the condition `shield_bypassable_adaptive` when the attack succeeds unnoticed too often.
"""
import argparse
import json
from datetime import datetime, timezone

import numpy as np
import torch

from app.ai import model, shield
from app.config import settings
from app.imaging import display_pixels, load_image

EPS = [1, 2]
STEPS = 60
MARGIN = 0.05
BATCH = 10


def held_out(want_sick: bool, n: int) -> torch.Tensor:
    nih = settings.data_dir / "nih"
    files = sorted((nih / "normal").glob("*.png")) + sorted((nih / "findings").glob("*.png"))
    idx = model.pathology_index()
    picked = []
    for path in files[1::2]:  # the half scripts.calibrate_shield holds out
        x = model.preprocess(display_pixels(load_image(path.read_bytes())))
        with torch.no_grad():
            sick = float(model.scores(x)[0, idx]) >= model.THRESHOLD
        if sick == want_sick:
            picked.append(x)
        if len(picked) == n:
            break
    return torch.cat(picked) if picked else torch.empty(0, 1, model.SIZE, model.SIZE)


def attack(x: torch.Tensor, eps_px: float, direction: int, threshold: float) -> torch.Tensor:
    idx = model.pathology_index()
    eps = eps_px * model.PX_TO_NORM
    x_adv = x.clone()
    for _ in range(STEPS):
        xa = x_adv.clone().requires_grad_(True)
        s = model.scores(xa)[:, idx]
        flip = torch.relu(direction * (model.THRESHOLD + direction * MARGIN - s))
        hide = torch.relu(shield.scores_t(xa) - 0.8 * threshold) / threshold
        (flip + hide).sum().backward()
        x_adv = x_adv - (eps / 6) * xa.grad.sign()
        x_adv = torch.max(torch.min(x_adv, x + eps), x - eps).clamp(model.LO, model.HI).detach()
    return x_adv


def evaluate(x: torch.Tensor, direction: int, eps_px: float, threshold: float) -> dict:
    idx = model.pathology_index()
    flipped, flagged = [], []
    for i in range(0, len(x), BATCH):
        adv = attack(x[i:i + BATCH], eps_px, direction, threshold)
        imgs = [model.to_uint8(adv[j:j + 1]) for j in range(len(adv))]  # as uploaded: 8-bit PNG
        q = torch.cat([model.preprocess(img) for img in imgs])
        with torch.no_grad():
            s = model.scores(q)[:, idx].numpy()
        flipped += list(s > model.THRESHOLD if direction > 0 else s < model.THRESHOLD)
        flagged += list(shield.distances(imgs) > threshold)
    flipped, flagged = np.array(flipped), np.array(flagged)
    return {
        "n": int(len(flipped)),
        "fooled_model": int(flipped.sum()),
        "detected_of_fooled": int((flipped & flagged).sum()),
        "silent_success": int((flipped & ~flagged).sum()),
        "silent_success_rate": round(float((flipped & ~flagged).mean()), 3) if len(flipped) else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30, help="images per direction")
    args = ap.parse_args()
    torch.manual_seed(0)
    c = json.loads(settings.shield_calibration.read_text())
    threshold = c["threshold"]

    sets = {"healthy_to_sick": (held_out(False, args.n), +1), "sick_to_healthy": (held_out(True, args.n), -1)}
    results = {}
    for eps in EPS:
        results[f"{eps:g}"] = {}
        for name, (x, direction) in sets.items():
            if len(x):
                r = evaluate(x, direction, eps, threshold)
                results[f"{eps:g}"][name] = r
                print(f"eps={eps:g} {name}: {r}", flush=True)

    worst_eps1 = max((r["silent_success_rate"] or 0) for r in results["1"].values())
    c["adaptive"] = {
        "method": f"white-box PGD on flip loss + shield score, {STEPS} steps, exact gradients through the squeezers",
        "squeezers": c.get("squeezers", ["median3"]),
        "results": results,
        "silent_success_eps1": worst_eps1,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    c["adaptive_attack_tested"] = True
    settings.shield_calibration.write_text(json.dumps(c, indent=2) + "\n")
    print("worst silent success at eps=1:", worst_eps1, "-> saved", settings.shield_calibration)


if __name__ == "__main__":
    main()

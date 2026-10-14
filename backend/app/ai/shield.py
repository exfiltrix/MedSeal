"""AI shield: feature squeezing (Xu et al., 2018) in front of the diagnostic model.

Adversarial noise is fragile: squeezing the image (median filter, fewer grey levels) wipes most
of it out, so the model's answer on an attacked image jumps after squeezing, while on a clean
image it barely moves.

    d_k   = sum over pathologies |logit(image) - logit(squeeze_k(image))|
    score = max over squeezers k of d_k / scale_k        (scale_k: median d_k on clean X-rays)

Raw logits, not the op_threshs-calibrated scores: calibration stretches small changes
near each threshold, which makes clean images look as unstable as attacked ones.
The threshold is the 99th percentile of the score on clean X-rays
(scripts/calibrate_shield.py -> shield_calibration.json), so ~1% of clean images are flagged.

Review round 1: v1 was a single median 3x3 (PIL). An adaptive attacker who optimises against it
(scripts/adaptive_attack.py) slipped past it in 73-100% of attempts. v2 runs an ensemble of three
squeezers, implemented in torch so the adaptive attack gets exact gradients through the very same
code the shield runs — the reported bypass rate is then a fair, not an optimistic, number.
"""
import json
import threading
from functools import lru_cache

import numpy as np
import torch
import torch.nn.functional as F

from app.ai import model
from app.config import settings

_CHECK_LOCK = threading.Lock()
SQUEEZERS = ("median3", "median2", "bits5")


def _median(u: torch.Tensor, k: int) -> torch.Tensor:
    """k x k median over [N, 1, H, W]; the output keeps the input size. Differentiable (selection)."""
    pad = (k // 2, (k - 1) // 2, k // 2, (k - 1) // 2) if k % 2 else (0, 1, 0, 1)
    padded = F.pad(u, pad, mode="replicate")
    patches = F.unfold(padded, kernel_size=k)  # [N, k*k, H*W]
    return patches.median(dim=1).values.view_as(u)


def squeeze(x: torch.Tensor, kind: str) -> torch.Tensor:
    """Squeeze a batch in the model's normalised space; returns the same space."""
    u = (x - model.LO) * 255.0 / (model.HI - model.LO)  # 0..255
    if kind == "median3":
        s = _median(u, 3)
    elif kind == "median2":
        s = _median(u, 2)
    elif kind == "bits5":
        q = torch.round(u / 255.0 * 31) / 31 * 255.0
        s = u + (q - u).detach()  # straight-through: rounding has no useful gradient of its own
    else:
        raise ValueError(f"unknown squeezer {kind}")
    return s * (model.HI - model.LO) / 255.0 + model.LO


def _logits(x: torch.Tensor) -> torch.Tensor:
    m = model.load_model()
    return m.classifier(m.features2(x))


def raw_distances(x: torch.Tensor, squeezers=SQUEEZERS) -> torch.Tensor:
    """[N, 1, 224, 224] normalised batch -> [N, len(squeezers)] squeeze distances. Differentiable."""
    base = _logits(x)
    return torch.stack([(base - _logits(squeeze(x, k))).abs().sum(dim=1) for k in squeezers], dim=1)


@lru_cache(maxsize=1)
def calibration() -> dict:
    return json.loads(settings.shield_calibration.read_text())


def scores_t(x: torch.Tensor) -> torch.Tensor:
    """[N] shield score for a normalised batch, as compared with the threshold. Differentiable."""
    c = calibration()
    squeezers = c.get("squeezers", ["median3"])
    scales = torch.tensor([c.get("scales", {}).get(k, 1.0) for k in squeezers])
    return (raw_distances(x, squeezers) / scales).max(dim=1).values


@torch.no_grad()
def distances(imgs: list[np.ndarray]) -> np.ndarray:
    """224x224 uint8 model-input images -> shield score per image."""
    return scores_t(torch.cat([model.preprocess(img) for img in imgs])).numpy()


def check(px: np.ndarray) -> dict:
    with _CHECK_LOCK:
        score = float(distances([model.model_input(px)])[0])
        threshold = calibration()["threshold"]
    return {"attack_suspected": score > threshold, "score": round(score, 3), "threshold": threshold}

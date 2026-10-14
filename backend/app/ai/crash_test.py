"""Crash test: attack the model and measure how often the diagnosis flips, in both directions —
N images it reads as healthy (pushed to sick) and N it reads as sick (pushed to healthy).

Robustness score = 10 x (1 - worst flip rate of the two directions at eps = 1 px), rounded to 1 decimal.
"""
import time
from collections.abc import Callable
from pathlib import Path

import torch

from app.ai import attacks, model
from app.config import settings
from app.imaging import ImageError, display_pixels, load_image
from app.verify.preview import render_preview

SCORE_EPS = 1.0
BATCH = 4  # fastest on a laptop CPU; 8 and 50 measured slower with per-image early stop
IMAGE_SUFFIXES = {".png", ".dcm"}


class CrashTestError(Exception):
    pass


HEALTHY_DIRS = ("nih/normal", "samples")
SICK_DIRS = ("nih/findings", "samples")


def image_files(dirs=HEALTHY_DIRS) -> list[Path]:
    paths = [settings.data_dir / d for d in dirs]
    return [p for d in paths if d.is_dir() for p in sorted(d.iterdir()) if p.suffix.lower() in IMAGE_SUFFIXES]


def load_images(n: int, pathology: str, sick: bool = False) -> tuple[torch.Tensor, list[str]]:
    """Up to n images the model scores below (sick=False) or at/above (sick=True) threshold for
    `pathology`, as a [k, 1, 224, 224] batch, plus the data folders they came from."""
    idx = model.pathology_index(pathology)
    picked, sources = [], set()
    for path in image_files(SICK_DIRS if sick else HEALTHY_DIRS):
        try:
            image = load_image(path.read_bytes())
            x = model.preprocess(display_pixels(image))
        except ImageError:
            continue
        with torch.no_grad():
            if (float(model.scores(x)[0, idx]) >= model.THRESHOLD) == sick:
                picked.append(x)
                sources.add(path.parent.relative_to(settings.data_dir).as_posix())
        if len(picked) == n:
            break
    if not picked:
        if sick:
            return torch.empty(0, 1, model.SIZE, model.SIZE), []
        raise CrashTestError(f"No test images found in {settings.data_dir}. Run: python -m scripts.fetch_dataset")
    return torch.cat(picked), sorted(sources)


def load_healthy(n: int, pathology: str) -> tuple[torch.Tensor, list[str]]:
    return load_images(n, pathology, sick=False)


def _key(eps: float) -> str:
    return f"{eps:g}"


def run(
    n_images: int,
    eps_list: list[float],
    method: str = "pgd",
    pathology: str = model.DEMO_PATHOLOGY,
    progress: Callable[[float], None] = lambda _: None,
) -> dict:
    t0 = time.perf_counter()
    eps_list = sorted(set(eps_list) | {SCORE_EPS})
    idx = model.pathology_index(pathology)
    attack = attacks.ATTACKS[method]
    kwargs = {"stop_when_flipped": True} if method == "pgd" else {}

    x, sources = load_healthy(n_images, pathology)
    # Review round 1: the score used to measure only healthy -> sick. Hiding a finding (sick ->
    # healthy) is the more dangerous flip, so it is measured too and the score takes the worse one.
    x_sick, sick_sources = load_images(n_images, pathology, sick=True)
    progress(0.1)

    n_batches = -(-len(x) // BATCH) + -(-len(x_sick) // BATCH)
    done, total = 0, len(eps_list) * n_batches

    def flip_rates(xs: torch.Tensor, sick: bool) -> tuple[dict, dict]:
        nonlocal done
        rates, psnr = {}, {}
        for eps in eps_list:
            flips, psnrs = 0, []
            for i in range(0, len(xs), BATCH):
                xb = xs[i:i + BATCH]
                xa = attack(xb, eps, pathology, **kwargs)
                with torch.no_grad():
                    s = model.scores(xa)[:, idx]
                flips += int((s < model.THRESHOLD).sum() if sick else (s > model.THRESHOLD).sum())
                psnrs += [attacks.psnr(xb[j:j + 1], xa[j:j + 1]) for j in range(len(xb))]
                done += 1
                progress(0.1 + 0.85 * done / total)
            rates[_key(eps)] = round(flips / len(xs), 3)
            psnr[_key(eps)] = round(sum(psnrs) / len(psnrs), 1)
        return rates, psnr

    flip_rate, psnr = flip_rates(x, sick=False)
    flip_rate_reverse = flip_rates(x_sick, sick=True)[0] if len(x_sick) else None
    worst = max(flip_rate[_key(SCORE_EPS)], (flip_rate_reverse or {}).get(_key(SCORE_EPS), 0.0))

    # Showcase pair for the UI: full-strength attack (no early stop) on the first image.
    before = x[:1]
    after = attack(before, SCORE_EPS, pathology)
    with torch.no_grad():
        s_before = float(model.scores(before)[0, idx])
        s_after = float(model.scores(after)[0, idx])
    progress(1.0)

    return {
        "n_requested": n_images,
        "n_images": len(x),
        "method": method,
        "pathology": pathology,
        "data": sources,
        "eps": eps_list,
        "flip_rate": flip_rate,
        "n_images_reverse": len(x_sick),
        "flip_rate_reverse": flip_rate_reverse,
        "data_reverse": sick_sources,
        "score_basis": "worst_direction" if flip_rate_reverse is not None else "healthy_to_sick",
        "psnr": psnr,
        "example": {
            "eps": SCORE_EPS,
            "before_png": render_preview(model.to_uint8(before)),
            "after_png": render_preview(model.to_uint8(after)),
            "before_score": round(s_before, 4),
            "after_score": round(s_after, 4),
        },
        "robustness_score": round(10 * (1 - worst), 1),
        "duration_s": round(time.perf_counter() - t0, 1),
    }

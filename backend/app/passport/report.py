"""Model passport: one frozen report per (model, crash test) with a verdict a regulator can read.

Verdict rules (deterministic, printed in the passport):
  robustness >= 7                       -> allowed                   (model is robust on its own)
  robustness <  7, shield compatible    -> allowed_with_conditions   (only behind the MedSeal shield)
  robustness <  7, no working shield    -> not_allowed
Shield compatible = calibrated, catches >= 90% of PGD attacks at eps 1 px, <= 2% false alarms.
"""
import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai.statistics import clopper_pearson
from app.config import settings
from app.models import AIModel, CrashTest, Device, Seal, Verification, iso_utc
from app.seal import anchors, ledger
from app.verify.service import DOCTOR_NOTE

ALLOW_SCORE = 7.0
SHIELD_MIN_DETECTION = 0.9
SHIELD_MAX_FALSE_ALARMS = 0.02
SCORE_FORMULA = "10 × (1 − worst flip rate of both directions at eps = 1 px)"

# P1-04: a passport may only be issued from a crash test that actually ran the protocol it
# claims to certify against — otherwise a cheap FGSM run on a handful of images could pass for
# the real thing. Torch-free on purpose (this module must not gain a hard torch dependency —
# passports are issued from a finished DB row, no model load required).
# v2 (review round 1): both directions must have been attacked — a test that never tried to hide a
# finding (sick -> healthy) cannot certify a model, and older one-direction tests must be re-run.
PROTOCOL = {"method": "pgd", "min_images": 50, "eps_required": [1], "min_images_reverse": 20, "version": 2}


def protocol_compliant(result: dict) -> bool:
    return (
        result.get("method") == PROTOCOL["method"]
        and result.get("n_images", 0) >= PROTOCOL["min_images"]
        and all(e in result.get("eps", []) for e in PROTOCOL["eps_required"])
        and result.get("flip_rate_reverse") is not None
        and result.get("n_images_reverse", 0) >= PROTOCOL["min_images_reverse"]
    )

VERDICTS = ("allowed", "allowed_with_conditions", "not_allowed")
# Condition codes; texts live in the frontend dictionary and in passport/i18n.py for the PDF.
SHIELD_REQUIRED = "shield_required"      # every image goes through the shield before the model
SEAL_REQUIRED = "seal_required"          # images sealed at capture and verified before the model
DOCTOR_DECIDES = "doctor_decides"        # model output is advice; the doctor makes the diagnosis
RETEST_REQUIRED = "retest_required"      # re-run the crash test after retraining (not_allowed)
CLINICAL_VALIDATION_REQUIRED = "clinical_validation_required"  # research score is not clinical clearance
# The shield was measured against an attacker who knows it (scripts/adaptive_attack.py) and let too
# many attacks through unnoticed: "behind the shield" then does not protect against that attacker.
SHIELD_BYPASSABLE = "shield_bypassable_adaptive"
ADAPTIVE_MAX_SILENT = 0.1  # worst direction, eps = 1 px


def model_json(m: AIModel) -> dict:
    return {"id": m.id, "name": m.name, "version": m.version, "source": m.source, "intended_use": m.intended_use}


def robustness_block(ct: CrashTest) -> dict:
    r = json.loads(ct.results_json)
    return {
        "score": ct.robustness_score,
        "formula": SCORE_FORMULA,
        "crash_test_id": ct.id,
        "tested_at": iso_utc(ct.created_at),
        "n_requested": r.get("n_requested", r["n_images"]),
        "n_images": r["n_images"],
        "method": r["method"],
        "pathology": r["pathology"],
        "data": r.get("data", []),
        "flip_rate": r["flip_rate"],
        "flip_rate_reverse": r.get("flip_rate_reverse"),
        "n_images_reverse": r.get("n_images_reverse", 0),
        "score_basis": r.get("score_basis", "healthy_to_sick"),
        "psnr": r["psnr"],
        "example": r.get("example"),  # before/after pair, base64 PNGs
    }


def _count_and_interval(rate: float, trials: int, count: int | None = None) -> dict:
    successes = int(count if count is not None else round(rate * trials))
    lower, upper = clopper_pearson(successes, trials)
    return {"successes": successes, "n": trials, "lower": round(lower, 6), "upper": round(upper, 6)}


def _worst(forward: dict, reverse: dict | None) -> dict:
    if not reverse or reverse.get("detected") is None:
        return forward
    return reverse if reverse["detected"] < (forward.get("detected") or 0) else forward


def shield_block() -> dict:
    path = settings.shield_calibration
    if not path.exists():
        return {"available": False, "compatible": False}
    c = json.loads(path.read_text())
    # Worst direction: a shield that only catches healthy -> sick attacks does not protect against
    # the more dangerous sick -> healthy one (review round 1; calibrations before it lack this block).
    pgd_entry = _worst(c["detection_rate"]["pgd"]["1"], (c.get("detection_rate_reverse") or {}).get("pgd", {}).get("1"))
    fgsm_entry = _worst(c["detection_rate"]["fgsm"]["1"], (c.get("detection_rate_reverse") or {}).get("fgsm", {}).get("1"))
    pgd1 = pgd_entry["detected"]
    fgsm1 = fgsm_entry["detected"]
    n_held_out = int(c["n_held_out"])
    fpr_count = c.get("false_positive_count")
    detection_ci = _count_and_interval(
        pgd1 or 0.0,
        int(pgd_entry["attacks_that_fooled_model"]),
        pgd_entry.get("detected_count"),
    )
    fpr_ci = _count_and_interval(c["false_positive_rate"], n_held_out, fpr_count)
    adaptive = c.get("adaptive")
    adaptive_rate = adaptive.get("silent_success_eps1") if adaptive else None
    return {
        "available": True,
        "method": c["method"],
        "threshold": c["threshold"],
        "false_positive_rate": c["false_positive_rate"],
        "detection_pgd_eps1": None if pgd1 is None else round(pgd1, 3),
        "detection_fgsm_eps1": None if fgsm1 is None else round(fgsm1, 3),
        "confidence_intervals": {
            "detection_pgd_eps1": detection_ci,
            "false_positive_rate": fpr_ci,
        },
        "directions_tested": 2 if c.get("detection_rate_reverse") else 1,
        "adaptive_attack_tested": adaptive is not None,
        "adaptive_silent_success_eps1": adaptive_rate,
        "bypassable": adaptive_rate is not None and adaptive_rate >= ADAPTIVE_MAX_SILENT,
        "calibrated_on": c["dataset"],
        # AI-01 (decided): the rule stays on point estimates. With the current calibration sample
        # (29/29 PGD detections, 4/450 false alarms) the 95% Clopper-Pearson interval does not yet
        # establish these thresholds on its own (see ARCHITECTURE.md) — the bounds are computed and
        # shown next to the point estimates instead of gating `compatible`.
        "compatible": (pgd1 or 0) >= SHIELD_MIN_DETECTION and c["false_positive_rate"] <= SHIELD_MAX_FALSE_ALARMS,
    }


def pipeline_block(session: Session) -> dict:
    """How well the image pipeline in front of the model is protected right now."""
    by_result = dict(session.execute(select(Verification.result, func.count()).group_by(Verification.result)).all())
    broken = ledger.broken_entries(session)
    _anchors_checked, anchor_mismatch = anchors.check_anchors(session)
    return {
        "devices_active": session.scalar(select(func.count(Device.id)).where(Device.revoked.is_(False))),
        "seals": session.scalar(select(func.count(Seal.id))),
        "verifications": sum(by_result.values()),
        "tampered_or_forged": by_result.get("tampered", 0) + by_result.get("forged", 0),
        "ledger_ok": not broken and not anchor_mismatch,
    }


def decide(
    score: float,
    shield_compatible: bool,
    clinical_validation: dict | None = None,
    shield_bypassable: bool = False,
) -> tuple[str, list[str]]:
    """Apply research thresholds; clinical validation is required for `allowed`."""
    validated = clinical_validation is not None
    if score >= ALLOW_SCORE and validated:
        return "allowed", [SEAL_REQUIRED, DOCTOR_DECIDES]
    if shield_compatible:
        conditions = [SHIELD_REQUIRED, SEAL_REQUIRED, DOCTOR_DECIDES]
        if shield_bypassable:
            conditions.insert(1, SHIELD_BYPASSABLE)
        if not validated:
            conditions.insert(0, CLINICAL_VALIDATION_REQUIRED)
        return "allowed_with_conditions", conditions
    if score >= ALLOW_SCORE:
        # Robust enough already: re-running the crash test would not change anything, the only
        # thing missing is clinical validation (asking for a retest here sent people the wrong way).
        return "not_allowed", [CLINICAL_VALIDATION_REQUIRED]
    if not validated:
        return "not_allowed", [CLINICAL_VALIDATION_REQUIRED, RETEST_REQUIRED]
    return "not_allowed", [RETEST_REQUIRED]


def build(session: Session, m: AIModel, ct: CrashTest) -> dict:
    """Everything the passport shows, without id/organisation/created_at (added when it is issued)."""
    robustness = robustness_block(ct)
    shield = shield_block()
    clinical_validation = json.loads(ct.results_json).get("clinical_validation")
    verdict, conditions = decide(robustness["score"], shield["compatible"], clinical_validation,
                                 shield.get("bypassable", False))
    return {
        "model": model_json(m),
        "robustness": robustness,
        "shield": shield,
        "clinical_validation": clinical_validation,
        "pipeline": pipeline_block(session),
        "verdict": verdict,
        "conditions": conditions,
        "rules": {
            "allow_score": ALLOW_SCORE,
            "shield_min_detection": SHIELD_MIN_DETECTION,
            "shield_max_false_alarms": SHIELD_MAX_FALSE_ALARMS,
            "clinical_validation_required": True,
        },
        "protocol": PROTOCOL,
        "note": DOCTOR_NOTE,
    }

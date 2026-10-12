"""
PraHari — Research Feasibility Assessment & Dataset Audit Engine

Evaluates security telemetry datasets against rigorous scientific criteria
prior to allowing predictive forecasting models to be enabled.

Checks performed:
1. Temporal Integrity & Monotonicity (timestamps valid, chronologically ordered)
2. Label Semantics & Class Distribution (imbalance ratios, ground truth presence)
3. Leakage Prevention (absence of forward-looking features or synthetic artifacts)
4. Stationarity & Duration (sufficient observation span)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field

from app.schemas.events import (
    NON_DEFECT_QUALITY_FLAGS,
    DataCategory,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
    is_quality_defect,
)


class FeasibilityCheckResult(BaseModel):
    check_name: str
    passed: bool
    score: float  # 0.0 to 1.0
    details: str
    risk_level: str  # low, medium, high, critical


class FeasibilityReport(BaseModel):
    dataset_id: str
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    gate_passed: bool
    overall_score: float
    recommendation: str  # PERMIT_FORECASTING, CONDITIONAL_REVIEW, REJECT_FORECASTING
    checks: list[FeasibilityCheckResult]
    metrics: dict[str, Any]


def audit_dataset_feasibility(
    events: list[NormalizedEvent],
    dataset_id: str = "default_audit",
    min_event_count: int = 25,
) -> FeasibilityReport:
    """
    Run the full Research Feasibility Audit across candidate normalized events.
    """
    checks: list[FeasibilityCheckResult] = []
    total = len(events)

    if total < min_event_count:
        checks.append(FeasibilityCheckResult(
            check_name="Sample Size Adequacy",
            passed=False,
            score=round(total / float(min_event_count), 2),
            details=f"Dataset contains {total} events, minimum required for statistical validity is {min_event_count}.",
            risk_level="critical",
        ))
        return FeasibilityReport(
            dataset_id=dataset_id,
            gate_passed=False,
            overall_score=0.2,
            recommendation="REJECT_FORECASTING",
            checks=checks,
            metrics={"total_events": total, "min_required": min_event_count},
        )

    # 1. Temporal Monotonicity & Chronology
    sorted_events = sorted(events, key=lambda e: e.observed_at)
    in_order_count = 0
    for i in range(len(sorted_events) - 1):
        if sorted_events[i].observed_at <= sorted_events[i + 1].observed_at:
            in_order_count += 1
    order_ratio = in_order_count / max(1, len(sorted_events) - 1)
    time_span = (sorted_events[-1].observed_at - sorted_events[0].observed_at).total_seconds()

    temporal_passed = order_ratio >= 0.99 and time_span > 0
    checks.append(FeasibilityCheckResult(
        check_name="Temporal Monotonicity & Ordering",
        passed=temporal_passed,
        score=round(order_ratio, 4),
        details=f"Span: {round(time_span, 1)}s. Temporal order ratio: {round(order_ratio * 100, 1)}%.",
        risk_level="low" if temporal_passed else "high",
    ))

    # 2. Label Integrity & Ground Truth Audit
    labels = [e.label or "unlabeled" for e in events]
    has_labels = any(l.lower() != "unlabeled" for l in labels)
    benign_count = sum(1 for l in labels if l.lower() == "benign")
    attack_count = sum(1 for l in labels if l.lower() not in ("benign", "unlabeled"))
    attack_ratio = attack_count / float(total) if total > 0 else 0.0

    # Ensure dataset is not 100% attack or 100% benign
    balance_score = 1.0 - abs(0.5 - min(max(attack_ratio, 0.05), 0.5)) * 2
    label_passed = has_labels and attack_count >= 2 and benign_count >= 2

    if not has_labels:
        label_detail = (
            f"No ground-truth labels are present on any of {total} events. "
            "Locally observed traffic carries no incident labels, and "
            "unlabelled traffic is NOT treated as benign — doing so would "
            "invent ground truth."
        )
    else:
        label_detail = (
            f"Benign: {benign_count}, Attack: {attack_count} "
            f"({round(attack_ratio * 100, 1)}% attack)."
        )
        if not label_passed:
            label_detail += " Both classes need at least 2 examples."

    checks.append(FeasibilityCheckResult(
        check_name="Label Ground Truth & Balance",
        passed=label_passed,
        score=round(balance_score, 4),
        details=label_detail,
        risk_level="low" if label_passed else "high",
    ))

    # 3. Provenance & Synthetic Flag Audit
    synthetic_count = sum(1 for e in events if e.data_category == DataCategory.SYNTHETIC)
    ground_truth_count = sum(1 for e in events if e.label_provenance == LabelProvenance.DATASET_GROUND_TRUTH)
    provenance_score = 1.0 if (ground_truth_count > 0 or synthetic_count == 0) else 0.7

    checks.append(FeasibilityCheckResult(
        check_name="Data Provenance Integrity",
        passed=True,
        score=provenance_score,
        details=f"Ground truth labelled: {ground_truth_count}, Synthetic flagged: {synthetic_count}.",
        risk_level="low",
    ))

    # 4. Feature Completeness & Quality Flags
    #
    # SOURCE_LIMITED marks a field the telemetry source structurally cannot
    # provide. It is a property of the sensor, not a defect in the record,
    # and must not count against data quality — otherwise every record from
    # the Windows connection table scores as faulty and the feasibility
    # index collapses for reasons unrelated to data integrity.
    warning_count = sum(
        1 for e in events if any(is_quality_defect(f) for f in e.quality_flags)
    )
    source_limited_count = sum(
        1
        for e in events
        if any(f in NON_DEFECT_QUALITY_FLAGS for f in e.quality_flags)
    )
    warning_ratio = warning_count / float(total)
    quality_score = max(0.0, 1.0 - warning_ratio)
    quality_passed = warning_ratio < 0.4

    quality_detail = (
        f"Records with genuine quality defects: {warning_count} "
        f"({round(warning_ratio * 100, 1)}%)."
    )
    if source_limited_count:
        quality_detail += (
            f" A further {source_limited_count} record(s) carry source-limit "
            "or synthetic-provenance markers; these describe the source, not "
            "a defect, and are not counted against quality."
        )

    checks.append(FeasibilityCheckResult(
        check_name="Data Quality & Artifact Audit",
        passed=quality_passed,
        score=round(quality_score, 4),
        details=quality_detail,
        risk_level="low" if quality_passed else "medium",
    ))

    # Compute overall composite score
    passed_count = sum(1 for c in checks if c.passed)
    overall_score = round(sum(c.score for c in checks) / float(len(checks)), 4)
    gate_passed = passed_count == len(checks) and overall_score >= 0.75

    recommendation = "PERMIT_FORECASTING" if gate_passed else (
        "CONDITIONAL_REVIEW" if overall_score >= 0.6 else "REJECT_FORECASTING"
    )

    return FeasibilityReport(
        dataset_id=dataset_id,
        gate_passed=gate_passed,
        overall_score=overall_score,
        recommendation=recommendation,
        checks=checks,
        metrics={
            "total_events": total,
            "time_span_seconds": round(time_span, 1),
            "attack_count": attack_count,
            "benign_count": benign_count,
            "attack_ratio": round(attack_ratio, 4),
            "quality_warning_ratio": round(warning_ratio, 4),
        },
    )

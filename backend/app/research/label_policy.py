"""
PraHari — Label Provenance Policy for Supervised Training (ADR-070)

Training read each event's label TEXT and never its provenance. So a
dataset could mix a corpus's ground truth with a detector's signatures, or
with a model's own earlier predictions, and every one of them was treated
as the same kind of fact. The feasibility audit did not catch it either:
its "Data Provenance Integrity" check was `passed=True` unconditionally.

The categories PraHari keeps distinct are not interchangeable evidence:

* dataset_ground_truth - the corpus's own labels, under its labelling rules
* analyst_annotation   - a person's judgement
* detector_output      - a detector's opinion that something matched a rule
* synthetic_rule /
  rule_based           - labels a rule generated, not observed outcomes
* model_prediction     - a model's output
* unlabeled            - no label at all

The policy
----------
1. **A model's predictions are never training or evaluation labels.**
   Training on them evaluates a model against itself. Refused outright.
2. **One declared provenance per experiment.** Mixing two would merge
   incompatible labels to increase the sample count, which the project
   explicitly forbids. Refused, with the breakdown.
3. Events with NO declared provenance (the schema default, `unlabeled`)
   that nonetheless carry label text are counted and reported, never
   silently promoted to ground truth.

What the policy cannot do: verify that a declared provenance is TRUE. An
adapter that mislabels a detector's output as ground truth defeats it.
The policy enforces the declarations; the dataset audit is where they are
checked against the source.
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

from pydantic import BaseModel, Field

from app.schemas.events import LabelProvenance, NormalizedEvent

NEVER_GROUND_TRUTH = {
    LabelProvenance.MODEL_PREDICTION: (
        "a model's own output - training or evaluating on it measures a "
        "model against itself"
    ),
}

# What a result trained on each provenance can be said to forecast. Used in
# the manifest so a metric is never read as more than its labels support.
EVIDENCE_CLASS = {
    LabelProvenance.DATASET_GROUND_TRUTH: "dataset_labels",
    LabelProvenance.ANALYST_ANNOTATION: "analyst_annotations",
    LabelProvenance.DETECTOR_OUTPUT: "detector_alerts",
    LabelProvenance.SYNTHETIC_RULE: "synthetic_only",
    LabelProvenance.RULE_BASED: "rule_generated",
}

EVIDENCE_MEANING = {
    "dataset_labels": (
        "Forecasts the dataset's own labels, under its labelling rules. Not "
        "automatically compromise, incident or scenario start."
    ),
    "analyst_annotations": "Forecasts analyst judgements, not verified outcomes.",
    "detector_alerts": (
        "Forecasts a DETECTOR'S ALERTS. It learns to anticipate that "
        "detector's rules, not that an incident occurred."
    ),
    "synthetic_only": (
        "SYNTHETIC-ONLY. Demonstrates that the pipeline runs; establishes "
        "nothing about real-world forecasting performance."
    ),
    "rule_generated": (
        "Labels produced by a rule. Forecasts the rule's output, not observed "
        "outcomes."
    ),
    "undeclared": (
        "Labels carry no declared provenance. Their meaning is unknown, so "
        "no claim about what is being forecast can be made."
    ),
    "none": "No labelled events: nothing supervised can be evaluated.",
}


class LabelProvenanceError(ValueError):
    """Training refused because the labels are not one coherent kind of evidence."""


class LabelPolicyResult(BaseModel):
    labelled_events: int
    declared_breakdown: dict[str, int] = Field(default_factory=dict)
    undeclared_labelled_events: int = 0
    label_provenance: Optional[str] = None
    evidence_class: str
    evidence_meaning: str


def assess_label_provenance(events: list[NormalizedEvent]) -> LabelPolicyResult:
    """Classify an event set's labels. Never raises; see enforce_label_policy."""
    labelled = [e for e in events if e.label is not None and str(e.label).strip()]
    declared = Counter(
        e.label_provenance for e in labelled
        if e.label_provenance is not LabelProvenance.UNLABELED
    )
    undeclared = sum(
        1 for e in labelled if e.label_provenance is LabelProvenance.UNLABELED
    )

    if len(declared) == 1:
        (provenance,) = declared
        evidence = EVIDENCE_CLASS.get(provenance, "undeclared")
        chosen: Optional[str] = provenance.value
    elif not declared:
        evidence = "undeclared" if undeclared else "none"
        chosen = None
    else:
        evidence = "mixed"
        chosen = None

    return LabelPolicyResult(
        labelled_events=len(labelled),
        declared_breakdown={p.value: n for p, n in sorted(declared.items(), key=lambda kv: kv[0].value)},
        undeclared_labelled_events=undeclared,
        label_provenance=chosen,
        evidence_class=evidence,
        evidence_meaning=EVIDENCE_MEANING.get(
            evidence,
            "Mixed label provenance: incompatible kinds of evidence were combined.",
        ),
    )


def enforce_label_policy(events: list[NormalizedEvent]) -> LabelPolicyResult:
    """
    Refuse a training set whose labels are not one coherent kind of evidence.

    Raises LabelProvenanceError (a ValueError, so existing callers that turn
    a ValueError into a 4xx keep working).
    """
    result = assess_label_provenance(events)

    forbidden = {
        LabelProvenance(p): n for p, n in result.declared_breakdown.items()
        if LabelProvenance(p) in NEVER_GROUND_TRUTH
    }
    if forbidden:
        reasons = "; ".join(
            f"{n} event(s) labelled by {p.value}: {NEVER_GROUND_TRUTH[p]}"
            for p, n in forbidden.items()
        )
        raise LabelProvenanceError(f"Training refused. {reasons}.")

    if result.evidence_class == "mixed":
        raise LabelProvenanceError(
            "Training refused: the labelled events mix provenances "
            f"{result.declared_breakdown}. These are different kinds of "
            "evidence and are not merged to increase the sample count. "
            "Select one provenance per experiment."
        )
    return result

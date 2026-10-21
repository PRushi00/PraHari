"""
PraHari — Structured Forecasting Target Specification (ADR-070)

The experiment manifest recorded the target as one sentence of prose,
`y=1 if an attack-labelled event occurs in (t+L, t+L+H]...`. Prose cannot be
compared, versioned or checked, and it left most of the target's rules
unstated: what counts as a negative, what happens at a capture gap, what a
late event does, how a warning is matched.

This module states every rule as a field, built from the parameters the
pipeline ACTUALLY used, and fingerprints it. Each field describes what the
code does today - including where that falls short of the blueprint - not
what a target ideally should be.
"""

from __future__ import annotations

import hashlib
import json
from typing import Optional

from pydantic import BaseModel, Field

TARGET_ID = "prahari.attack_label_in_horizon"
# 1.0.0 - the rules as the pipeline applied them before this module.
# 1.1.0 - prediction-time availability: late live events are excluded from
#         earlier windows' features (ADR-069).
# 1.2.0 - event-level matching exists (ADR-091): warning aggregation,
#         suppression and event matching are defined, so the window-level
#         rules below now say which scope they apply to rather than
#         declaring event-level measurement absent.
TARGET_VERSION = "1.2.0"

NOT_EQUIVALENT_TO = [
    "scenario start - a dataset's recorded schedule, not an observation",
    "first labelled malicious flow - the first flow a labelling rule marked",
    "system compromise - not observable from flow labels alone",
    "confirmed incident - requires investigation the labels do not record",
]

ATTACK_LABEL_RULE = (
    "a label is an ATTACK label when it is non-empty and its lower-cased, "
    "trimmed text is not one of: benign, normal, unlabeled"
)

NON_ATTACK_LABELS = frozenset({"benign", "normal", "unlabeled", ""})


def is_attack_label(label: Optional[str]) -> bool:
    """`ATTACK_LABEL_RULE` as code, so the prose and the test agree."""
    return bool(label) and label.strip().lower() not in NON_ATTACK_LABELS


class TargetSpecification(BaseModel):
    target_id: str = TARGET_ID
    target_version: str = TARGET_VERSION

    event_semantics: str
    not_equivalent_to: list[str] = Field(default_factory=lambda: list(NOT_EQUIVALENT_TO))
    label_provenance: Optional[str] = None
    evidence_class: str = "none"
    evidence_meaning: str = ""

    grouping: str
    time_origin: str
    observation_window_seconds: float
    lead_time_seconds: float
    horizon_seconds: float
    stride_seconds: float
    overlap_handling: str

    positive_rule: str
    negative_rule: str
    incomplete_window_rule: str
    capture_gap_rule: str
    ongoing_attack_rule: str
    late_event_rule: str
    warning_matching: str
    warning_suppression: str

    scope_limitations: list[str] = Field(default_factory=list)

    def fingerprint(self) -> str:
        """SHA-256 of the canonical specification. Equal rules, equal hash."""
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_target_specification(
    *,
    window_seconds: float,
    lead_seconds: float,
    horizon_seconds: float,
    stride_seconds: float,
    min_horizon_events: int,
    require_labelled_horizon: bool,
    exclude_ongoing_attack_windows: bool,
    label_provenance: Optional[str] = None,
    evidence_class: str = "none",
    evidence_meaning: str = "",
) -> TargetSpecification:
    W, L, H, S = window_seconds, lead_seconds, horizon_seconds, stride_seconds
    negative = (
        f"y=0 only when the horizon holds at least {min_horizon_events} observed "
        "event(s), none of them an attack"
    )
    if require_labelled_horizon:
        negative += ", and at least one of them carries a label (so benignity is evidenced)"
    negative += ". Any other window is EXCLUDED, never labelled 0."

    limitations = [
        "The metrics in THIS specification are per WINDOW: `detected_events`, "
        "`missed_events` and `false_alarms` count windows, not distinct attack "
        "events, so one long attack spanning many windows is counted many "
        "times. Event-level counting lives in the separate event-level report "
        "(ADR-091), which is where an event-level claim must be read from.",
        "Event-level lead time (first qualifying warning to the event) is NOT "
        "measured by this window-level target. It is measured by the "
        "event-level report, under its own stated and fingerprinted matching "
        "rules; a lead time quoted without those rules is not comparable. The "
        "lead-time CURVE remains a different thing again: performance across "
        "configured lead offsets, each a separately trained model.",
        "Warning suppression is not modelled HERE: at window level every "
        "positive window is a separate warning, so this false-alarm burden is "
        "an upper bound on what an analyst with de-duplication would see. The "
        "event-level report applies a stated suppression interval and reports "
        "the alarm duty cycle beside the warning count.",
        "Trained models classify at a fixed probability of 0.5, never tuned, "
        "so no test data can influence the threshold; it is also not optimised "
        "on validation data, so the operating point may not suit a deployment. "
        "The rate-threshold baseline fits its own cut-offs (medians over "
        "positive TRAINING windows) on training data only.",
        "Offline replay of a historical import assumes each event was available "
        "at its own event time; real arrival delay for imported data is unknown.",
        "The horizon is the half-open interval [t+L, t+L+H). The blueprint's "
        "(t, t+H] corresponds to L=0 with the boundary instant assigned to the "
        "next window.",
    ]
    if evidence_class == "synthetic_only":
        limitations.insert(0, "Labels are SYNTHETIC: results establish nothing about real-world performance.")
    elif evidence_class in ("none", "undeclared", "mixed"):
        limitations.insert(0, f"Label evidence is '{evidence_class}': no forecasting claim is supported.")

    return TargetSpecification(
        event_semantics=(
            "At least one event in the horizon carries an attack label. "
            + ATTACK_LABEL_RULE + ". The label's meaning is that of its "
            "provenance - see evidence_meaning - and nothing stronger."
        ),
        label_provenance=label_provenance,
        evidence_class=evidence_class,
        evidence_meaning=evidence_meaning,
        grouping=(
            "None: all selected events form one chronological stream. Windows "
            "are not grouped by host, session or scenario."
        ),
        time_origin=(
            "The prediction time t is the END of the observation window. Features "
            f"use events observed in [t-{W:g}s, t); the horizon is [t+{L:g}s, t+{L + H:g}s)."
        ),
        observation_window_seconds=W,
        lead_time_seconds=L,
        horizon_seconds=H,
        stride_seconds=S,
        overlap_handling=(
            f"Windows advance by {S:g}s"
            + (f" and overlap when the stride is shorter than the {W:g}s window" if S < W else "")
            + ". Train and test are split chronologically by window order. The "
            f"ceil((W+L+H)/S) = ceil({W + L + H:g}/{S:g}) windows before the test "
            "start, less one, are purged from TRAINING, so no training window's "
            "observation or horizon overlaps a test window's data."
        ),
        positive_rule="y=1 when an attack label occurs anywhere in the horizon. A positive is always valid: its evidence is present.",
        negative_rule=negative,
        incomplete_window_rule=(
            "Windows are generated only while t+L+H lies within the observed span, "
            "so no window has a horizon that runs past the end of the data. A "
            "window cap, when reached, is reported as truncation."
        ),
        capture_gap_rule=(
            "A horizon with no observed events is a capture gap, not evidence of "
            "absence: the window is excluded and counted."
        ),
        ongoing_attack_rule=(
            "Windows whose observation interval already contains an attack are "
            + ("EXCLUDED" if exclude_ongoing_attack_windows else "KEPT and counted")
            + "; keeping them lets a model 'forecast' an attack already under way."
        ),
        late_event_rule=(
            "A LIVE event whose server receipt time is after t is excluded from "
            "that window's features (ADR-069). Excluded (window, event) pairs are "
            "reported. Imported and unstamped events are treated as available at "
            "their event time."
        ),
        warning_matching=(
            "A warning is a window the model classifies positive (probability "
            ">= 0.5 for trained models). It matches when that window's "
            "own horizon is positive. There is no event-level matching."
        ),
        warning_suppression="None. Each positive window is an independent warning.",
        scope_limitations=limitations,
    )

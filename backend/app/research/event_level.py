"""
PraHari — Event-Level Warning Evaluation (ADR-091)

Every metric the system reported until now counted **windows**. Blueprint
§10 asks a different question:

    "Event-level lead time: time between first qualifying warning and
     documented event; report late warnings and events with no warning."

A window-level recall of 0.9 does not answer it. One attack spanning forty
windows is one event an analyst must catch, not forty; forty consecutive
positive windows are one alert an analyst must read, not forty. Counting
windows therefore inflates both the credit and the burden, and it cannot
produce a lead time at all, because a window has no "first warning".

This module converts a window-level holdout into the event-level view:

* **Documented events** — runs of attack-labelled events, grouped into
  episodes. The event's time origin is the first attack-labelled record in
  the episode. That origin is *not* compromise time (see
  `target.NOT_EQUIVALENT_TO`); it is the first moment the labels evidence.
* **Warnings** — runs of positive windows collapsed by a suppression
  interval, so a sustained alarm counts once.
* **Matching** — fixed rules, stated as data and fingerprinted, so the
  protocol is frozen before the result is read. Blueprint §15 requires
  exactly that: "define warning aggregation, suppression, and event
  matching before test evaluation."

Nothing here invents an event, a warning, or a lead time. An event the
evaluated windows could never have warned about is excluded from the
denominator and counted, rather than scored as a miss the model had no
opportunity to avoid; and when no documented event lies in the evaluated
period, the report refuses rather than returning a perfect score over
nothing.
"""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_left, bisect_right
from datetime import datetime, timedelta
from typing import Literal, Optional

import numpy as np
from pydantic import BaseModel, Field

from app.research.target import ATTACK_LABEL_RULE, is_attack_label
from app.schemas.events import LabelProvenance, NormalizedEvent

# Two attack-labelled records closer together than this belong to the same
# documented event. The blueprint does not fix a value: it is a property of
# the corpus and the labelling rule, so it is a stated parameter, not a
# constant of the system.
DEFAULT_EPISODE_GAP_SECONDS = 300.0

# A sustained alarm is one warning. Within this interval of the previous
# contributing window, a further positive window extends the open warning
# instead of raising a new one.
DEFAULT_SUPPRESSION_SECONDS = 300.0

# The operating point. Fixed, never tuned on the holdout.
DEFAULT_THRESHOLD = 0.5


# ──────────────────────────────────────────────────────────────────
# The rules, as data
# ──────────────────────────────────────────────────────────────────


class MatchingRules(BaseModel):
    """
    The protocol, frozen and fingerprinted before any result is read.

    Every field is a decision that would otherwise be made implicitly —
    and could otherwise be made *after* seeing the numbers.
    """

    episode_gap_seconds: float
    min_lead_seconds: float
    max_lead_seconds: float
    suppression_seconds: float
    threshold: float

    attack_label_rule: str = ATTACK_LABEL_RULE
    event_time_origin: str = (
        "The first attack-labelled record of the episode. This is what the "
        "labels evidence, not the start of the scenario and not the moment "
        "of compromise."
    )
    episode_rule: str = ""
    warning_rule: str = ""
    qualifying_rule: str = ""
    reuse_rule: str = (
        "A warning is consumed by at most one event: the earliest event it "
        "qualifies for. A second event that only the same warning could have "
        "covered is counted as missed rather than credited twice."
    )
    coverage_rule: str = (
        "An event is in scope only when at least one evaluated prediction "
        "time falls in its qualifying interval. An event the holdout windows "
        "could never have warned about is excluded and counted, not scored "
        "as a miss."
    )
    late_rule: str = (
        "A warning issued inside an event's span that did not qualify as "
        "advance notice is LATE: reported separately, counted neither as a "
        "detection nor as a false alarm."
    )

    def model_post_init(self, _context: object) -> None:
        if not self.episode_rule:
            self.episode_rule = (
                "Attack-labelled records no more than "
                f"{self.episode_gap_seconds:g}s apart form one documented event."
            )
        if not self.warning_rule:
            self.warning_rule = (
                f"A window scoring >= {self.threshold:g} opens a warning. A "
                f"further positive window within {self.suppression_seconds:g}s "
                "of the previous contributing window extends it instead of "
                "raising a new one."
            )
        if not self.qualifying_rule:
            self.qualifying_rule = (
                "A warning qualifies for an event when it was issued between "
                f"{self.min_lead_seconds:g}s and {self.max_lead_seconds:g}s "
                "before the event's time origin. The bounds come from the "
                "target's own lead and horizon: a window predicting at t "
                "claims the interval [t+L, t+L+H)."
            )

    def fingerprint(self) -> str:
        """SHA-256 of the canonical rules. Equal rules, equal hash."""
        canonical = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ──────────────────────────────────────────────────────────────────
# What was found
# ──────────────────────────────────────────────────────────────────


class DocumentedEvent(BaseModel):
    """One episode of attack-labelled activity, and how it was warned."""

    event_index: int
    started_at: datetime
    ended_at: datetime
    labelled_records: int
    labels: list[str] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)

    in_coverage: bool = True
    out_of_coverage_reason: Optional[str] = None

    warned: bool = False
    lead_time_seconds: Optional[float] = None
    detecting_warning_index: Optional[int] = None
    late_warning_indices: list[int] = Field(default_factory=list)


class IssuedWarning(BaseModel):
    """One aggregated warning: a run of positive windows, counted once."""

    warning_index: int
    issued_at: datetime
    last_window_at: datetime
    windows: int
    peak_score: float
    outcome: Literal["detection", "late", "false_alarm"] = "false_alarm"
    matched_event_index: Optional[int] = None
    lead_time_seconds: Optional[float] = None


class LeadTimeDistribution(BaseModel):
    """
    The distribution, never a bare mean.

    A mean lead time over two events is not a measurement, so the count is
    carried beside every statistic and the quartiles are refused below four
    observations rather than computed from one or two.
    """

    count: int = 0
    min_seconds: Optional[float] = None
    p25_seconds: Optional[float] = None
    median_seconds: Optional[float] = None
    p75_seconds: Optional[float] = None
    max_seconds: Optional[float] = None
    mean_seconds: Optional[float] = None
    quartiles_available: bool = False
    note: str = ""


class ScenarioPerformance(BaseModel):
    """
    Warning performance for one attack scenario (§10, ADR-113).

    §10 asks for scenario-level performance, which the overall figures
    cannot give: a model that warns reliably about one attack family and
    never about another reports a respectable aggregate missed-event
    rate while being useless for half its job.

    The scenario is the attack LABEL the documented event carries. The
    schema has no separate scenario identifier, and inventing one would
    mean guessing which records belong to which campaign; the label is
    what the corpus actually states.
    """

    scenario: str
    events_total: int = 0
    events_warned: int = 0
    events_missed: int = 0
    missed_event_rate: Optional[float] = None
    lead_time: LeadTimeDistribution = Field(default_factory=LeadTimeDistribution)


class EventLevelReport(BaseModel):
    """Event-level warning performance under one frozen matching protocol."""

    available: bool = False
    refusal_reason: Optional[str] = None
    model_id: Optional[str] = None

    rules: MatchingRules
    rules_fingerprint: str = ""

    # Coverage
    evaluated_windows: int = 0
    first_prediction_at: Optional[datetime] = None
    last_prediction_at: Optional[datetime] = None
    evaluated_span_seconds: float = 0.0
    events_out_of_coverage: int = 0

    # Events
    events_total: int = 0
    events_warned: int = 0
    events_missed: int = 0
    missed_event_rate: Optional[float] = None
    lead_time: LeadTimeDistribution = Field(default_factory=LeadTimeDistribution)

    # Warnings
    positive_windows: int = 0
    warnings_issued: int = 0
    windows_per_warning: Optional[float] = None
    # Suppression collapses a continuous alarm into ONE warning, so a model
    # that alarms permanently reports a low warning count. The duty cycle is
    # carried beside it so that cannot be read as precision.
    alarm_duty_cycle: Optional[float] = None
    detections: int = 0
    late_warnings: int = 0
    false_alarms: int = 0
    false_alarms_per_hour: Optional[float] = None

    label_provenance: list[str] = Field(default_factory=list)
    events: list[DocumentedEvent] = Field(default_factory=list)
    by_scenario: list[ScenarioPerformance] = Field(default_factory=list)
    scenarios_note: str = ""
    warnings_detail: list[IssuedWarning] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.available and self.events_total > 0


# ──────────────────────────────────────────────────────────────────
# Construction
# ──────────────────────────────────────────────────────────────────


def build_documented_events(
    events: list[NormalizedEvent],
    episode_gap_seconds: float = DEFAULT_EPISODE_GAP_SECONDS,
) -> list[DocumentedEvent]:
    """
    Group attack-labelled records into episodes.

    Consecutive attack-labelled records no more than `episode_gap_seconds`
    apart are one documented event. Only the labels decide: a gap in
    *collection* that happens to exceed the threshold will split one real
    attack into two documented events, which is a limitation of labelling,
    not a judgement this function can make.
    """
    attack_records = sorted(
        (e for e in events if is_attack_label(e.label)),
        key=lambda e: e.observed_at,
    )
    if not attack_records:
        return []

    episodes: list[list[NormalizedEvent]] = [[attack_records[0]]]
    for record in attack_records[1:]:
        gap = (record.observed_at - episodes[-1][-1].observed_at).total_seconds()
        if gap <= episode_gap_seconds:
            episodes[-1].append(record)
        else:
            episodes.append([record])

    documented: list[DocumentedEvent] = []
    for index, episode in enumerate(episodes):
        documented.append(
            DocumentedEvent(
                event_index=index,
                started_at=episode[0].observed_at,
                ended_at=episode[-1].observed_at,
                labelled_records=len(episode),
                labels=sorted({e.label for e in episode if e.label}),
                source_ids=sorted({e.source_id for e in episode if e.source_id}),
            )
        )
    return documented


def aggregate_warnings(
    prediction_times: list[datetime],
    scores: np.ndarray,
    threshold: float = DEFAULT_THRESHOLD,
    suppression_seconds: float = DEFAULT_SUPPRESSION_SECONDS,
) -> list[IssuedWarning]:
    """
    Collapse runs of positive windows into warnings.

    Without this, a sustained alarm is counted as one false alarm per
    window and the analyst burden is reported as tens of alerts where an
    operator with ordinary de-duplication would see one.
    """
    order = sorted(range(len(prediction_times)), key=lambda i: prediction_times[i])
    warnings_: list[IssuedWarning] = []

    for position in order:
        score = float(scores[position])
        if score < threshold:
            continue
        at = prediction_times[position]
        if warnings_:
            open_warning = warnings_[-1]
            within = (at - open_warning.last_window_at).total_seconds()
            if within <= suppression_seconds:
                open_warning.windows += 1
                open_warning.last_window_at = at
                open_warning.peak_score = max(open_warning.peak_score, score)
                continue
        warnings_.append(
            IssuedWarning(
                warning_index=len(warnings_),
                issued_at=at,
                last_window_at=at,
                windows=1,
                peak_score=score,
            )
        )
    return warnings_


def _distribution(leads: list[float]) -> LeadTimeDistribution:
    """Percentiles over the measured leads, refusing quartiles below four."""
    if not leads:
        return LeadTimeDistribution(
            count=0, note="No event was warned in advance, so there is no lead time to report."
        )
    array = np.asarray(sorted(leads), dtype=float)
    dist = LeadTimeDistribution(
        count=len(leads),
        min_seconds=round(float(array.min()), 3),
        max_seconds=round(float(array.max()), 3),
        median_seconds=round(float(np.median(array)), 3),
        mean_seconds=round(float(array.mean()), 3),
    )
    if len(leads) >= 4:
        dist.p25_seconds = round(float(np.percentile(array, 25)), 3)
        dist.p75_seconds = round(float(np.percentile(array, 75)), 3)
        dist.quartiles_available = True
    else:
        dist.note = (
            f"{len(leads)} warned event(s): too few for quartiles, which would "
            "describe which single events happened to land in the test period."
        )
    return dist


def evaluate_event_level(
    events: list[NormalizedEvent],
    prediction_times: list[datetime],
    scores: np.ndarray,
    *,
    lead_seconds: float,
    horizon_seconds: float,
    model_id: Optional[str] = None,
    episode_gap_seconds: float = DEFAULT_EPISODE_GAP_SECONDS,
    suppression_seconds: float = DEFAULT_SUPPRESSION_SECONDS,
    threshold: float = DEFAULT_THRESHOLD,
) -> EventLevelReport:
    """
    Match aggregated warnings to documented events and measure lead time.

    `prediction_times` and `scores` are one evaluated holdout — the window
    end times and that model's scores, in the same order. `events` is the
    event stream the holdout was built from; only the documented events
    inside the holdout's coverage are scored.

    The qualifying interval comes from the target itself: a window
    predicting at *t* claims the horizon [t+L, t+L+H), so a warning issued
    at *t* qualifies for an event starting in that interval. Matching is
    therefore not a separate set of thresholds that could be tuned until
    the numbers improve.
    """
    rules = MatchingRules(
        episode_gap_seconds=episode_gap_seconds,
        min_lead_seconds=lead_seconds,
        max_lead_seconds=lead_seconds + horizon_seconds,
        suppression_seconds=suppression_seconds,
        threshold=threshold,
    )
    report = EventLevelReport(rules=rules, rules_fingerprint=rules.fingerprint(), model_id=model_id)

    scores = np.asarray(scores, dtype=float)
    if len(prediction_times) != len(scores):
        report.refusal_reason = (
            f"{len(prediction_times)} prediction time(s) against {len(scores)} "
            "score(s). Scoring a model's output against another model's "
            "window times would silently misalign them."
        )
        return report
    if not prediction_times:
        report.refusal_reason = "The holdout contains no evaluated windows."
        return report

    ordered_times = sorted(prediction_times)
    report.evaluated_windows = len(ordered_times)
    report.first_prediction_at = ordered_times[0]
    report.last_prediction_at = ordered_times[-1]
    report.evaluated_span_seconds = round(
        (ordered_times[-1] - ordered_times[0]).total_seconds(), 3
    )
    report.positive_windows = int((scores >= threshold).sum())
    report.label_provenance = sorted(
        {
            e.label_provenance.value
            for e in events
            if is_attack_label(e.label) and e.label_provenance is not None
        }
    )

    documented = build_documented_events(events, episode_gap_seconds)
    if not documented:
        report.refusal_reason = (
            "No attack-labelled record in the stream, so there is no "
            "documented event to warn about. A false-alarm count without a "
            "single real event is not an evaluation."
        )
        return report

    # Coverage: an event is in scope only if some evaluated window could
    # have warned for it. Scoring an event the holdout could never reach
    # would record a miss the model had no opportunity to avoid.
    for event in documented:
        window_lo = event.started_at - timedelta(seconds=rules.max_lead_seconds)
        window_hi = event.started_at - timedelta(seconds=rules.min_lead_seconds)
        if bisect_left(ordered_times, window_lo) >= bisect_right(ordered_times, window_hi):
            event.in_coverage = False
            event.out_of_coverage_reason = (
                "No evaluated window has a prediction time in this event's "
                f"qualifying interval [{window_lo.isoformat()}, "
                f"{window_hi.isoformat()}]."
            )

    in_scope = [e for e in documented if e.in_coverage]
    report.events_out_of_coverage = len(documented) - len(in_scope)
    if not in_scope:
        report.events = documented
        report.refusal_reason = (
            f"All {len(documented)} documented event(s) fall outside the "
            "evaluated holdout's reach: no evaluated window could have warned "
            "for any of them. Reporting a missed-event rate here would blame "
            "the model for windows it was never given."
        )
        return report

    warnings_ = aggregate_warnings(
        ordered_times, _scores_in_time_order(prediction_times, scores),
        threshold, suppression_seconds,
    )
    report.warnings_issued = len(warnings_)
    if warnings_:
        report.windows_per_warning = round(
            sum(w.windows for w in warnings_) / len(warnings_), 3
        )
    if report.evaluated_windows:
        report.alarm_duty_cycle = round(
            report.positive_windows / report.evaluated_windows, 4
        )

    # Match: each event takes its EARLIEST qualifying warning, which is what
    # "first qualifying warning" in the blueprint means. Each warning is
    # consumed once.
    claimed: set[int] = set()
    for event in sorted(in_scope, key=lambda e: e.started_at):
        window_lo = event.started_at - timedelta(seconds=rules.max_lead_seconds)
        window_hi = event.started_at - timedelta(seconds=rules.min_lead_seconds)
        for warning in warnings_:
            if warning.warning_index in claimed:
                continue
            if window_lo <= warning.issued_at <= window_hi:
                lead = (event.started_at - warning.issued_at).total_seconds()
                event.warned = True
                event.lead_time_seconds = round(lead, 3)
                event.detecting_warning_index = warning.warning_index
                warning.outcome = "detection"
                warning.matched_event_index = event.event_index
                warning.lead_time_seconds = round(lead, 3)
                claimed.add(warning.warning_index)
                break

    # Late: issued while the event was already under way.
    for warning in warnings_:
        if warning.outcome == "detection":
            continue
        for event in in_scope:
            if event.started_at <= warning.issued_at <= event.ended_at:
                warning.outcome = "late"
                warning.matched_event_index = event.event_index
                event.late_warning_indices.append(warning.warning_index)
                break

    report.detections = sum(1 for w in warnings_ if w.outcome == "detection")
    report.late_warnings = sum(1 for w in warnings_ if w.outcome == "late")
    report.false_alarms = sum(1 for w in warnings_ if w.outcome == "false_alarm")
    if report.evaluated_span_seconds > 0:
        report.false_alarms_per_hour = round(
            report.false_alarms / (report.evaluated_span_seconds / 3600.0), 3
        )

    report.events_total = len(in_scope)
    report.events_warned = sum(1 for e in in_scope if e.warned)
    report.events_missed = report.events_total - report.events_warned
    report.missed_event_rate = round(report.events_missed / report.events_total, 4)
    report.lead_time = _distribution(
        [e.lead_time_seconds for e in in_scope if e.lead_time_seconds is not None]
    )

    # Per-scenario breakdown (§10, ADR-113). An episode can carry more
    # than one label — ADR-095 found two distinct attacks sharing one
    # label in this very corpus — so an event is counted under EACH of
    # its labels. The per-scenario totals can therefore exceed
    # events_total, and the note says so rather than letting a reader
    # add them up and find a discrepancy.
    by_label: dict[str, list] = {}
    for ev in in_scope:
        for label in (ev.labels or ["(unlabelled)"]):
            by_label.setdefault(label, []).append(ev)

    scenarios: list[ScenarioPerformance] = []
    for label in sorted(by_label):
        group = by_label[label]
        warned = sum(1 for e in group if e.warned)
        scenarios.append(
            ScenarioPerformance(
                scenario=label,
                events_total=len(group),
                events_warned=warned,
                events_missed=len(group) - warned,
                missed_event_rate=round((len(group) - warned) / len(group), 4),
                lead_time=_distribution(
                    [e.lead_time_seconds for e in group
                     if e.lead_time_seconds is not None]
                ),
            )
        )
    report.by_scenario = scenarios
    multi = sum(1 for e in in_scope if len(e.labels or []) > 1)
    report.scenarios_note = (
        f"Scenario is the attack label the event carries; the schema has no "
        f"separate scenario identifier. {multi} of {len(in_scope)} event(s) "
        "carry more than one label and are counted under each, so these "
        "totals can exceed events_total."
    )

    report.events = documented
    report.warnings_detail = warnings_
    report.available = True
    report.limitations = _limitations(report)
    return report


def _scores_in_time_order(
    prediction_times: list[datetime], scores: np.ndarray
) -> np.ndarray:
    """Reorder scores to match the chronologically sorted times."""
    order = sorted(range(len(prediction_times)), key=lambda i: prediction_times[i])
    return scores[np.asarray(order, dtype=int)]


def _limitations(report: EventLevelReport) -> list[str]:
    """What this report does NOT establish, stated with the numbers."""
    limitations = [
        "An event's time origin is its first attack-LABELLED record. It is not "
        "the scenario start, not the first malicious action, and not the moment "
        "of compromise; a lead time is measured against the labels, so it "
        "inherits whatever delay the labelling rule carries.",
        "Episode grouping and suppression are parameters, not findings. A "
        "longer episode gap merges events and raises the apparent lead time; a "
        "longer suppression interval lowers the false-alarm count. Both are in "
        "`rules` and in the fingerprint so a comparison can check they match.",
        "The operating point is fixed, never tuned on this holdout. A different "
        "threshold would trade missed events against false alarms, and the "
        "trade-off is not explored here.",
    ]
    if report.alarm_duty_cycle is not None and report.alarm_duty_cycle >= 0.5:
        limitations.insert(
            0,
            f"The alarm was active for {report.alarm_duty_cycle:.0%} of the "
            "evaluated windows. Suppression collapses a continuous alarm into "
            f"one warning, so the {report.false_alarms} false alarm(s) reported "
            "here describe a model that is alarming almost always - not a quiet "
            "one. Read the duty cycle, not the warning count.",
        )
    provenance = set(report.label_provenance)
    if provenance & {
        LabelProvenance.SYNTHETIC_RULE.value,
        LabelProvenance.RULE_BASED.value,
    }:
        limitations.insert(
            0,
            "The documented events are SYNTHETIC or rule-derived. Every number "
            "below describes behaviour on invented data and establishes nothing "
            "about real-world warning performance.",
        )
    if LabelProvenance.DETECTOR_OUTPUT.value in provenance:
        limitations.insert(
            0,
            "Some documented events rest on DETECTOR OUTPUT: a detector's "
            "opinion, not a confirmed incident. A lead time against it measures "
            "agreement with that detector, not early warning of an attack.",
        )
    if report.events_out_of_coverage:
        limitations.append(
            f"{report.events_out_of_coverage} documented event(s) lay outside "
            "the evaluated windows' reach and are excluded from the rate; they "
            "are listed with their reason."
        )
    if report.events_total < 5:
        limitations.append(
            f"Only {report.events_total} documented event(s) are in scope. An "
            "event-level rate over so few is dominated by which events happened "
            "to fall in the test period."
        )
    if report.late_warnings:
        limitations.append(
            f"{report.late_warnings} warning(s) were issued while an event was "
            "already under way. They are neither detections nor false alarms: "
            "an analyst would still have seen them, but they gave no notice."
        )
    return limitations

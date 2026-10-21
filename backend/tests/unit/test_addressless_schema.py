"""
PraHari — The address-less feature schema (ADR-096).

Nine of the ten CSE-CIC-IDS2018 processed CSVs carry no `Src IP`, no
`Dst IP` and no `Flow ID`, so their endpoint addresses are unrecoverable.
Rejecting every row of those files loses nine days of labelled attacks —
including the only days with several separated attack onsets, which are
the only days that can support an honest chronological split.

The temptation is to accept them and let the two distinct-address
features compute `len(set()) == 0`. That is a **fabricated measurement**:
"no distinct source addresses were observed" is a claim about the
traffic, and a false one — the flows had addresses, the export dropped
them. These tests pin the alternative: the columns are REMOVED, the
resulting schema is a different, named schema, and a mixture of sources
is refused rather than silently undercounted.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.feature_extractor import (
    ADDRESS_DEPENDENT_FEATURES,
    ADDRESSLESS_FEATURE_NAMES,
    FEATURE_NAMES,
    FEATURE_SCHEMA_ADDRESSLESS,
    FEATURE_SCHEMA_FULL,
    MixedAddressAvailabilityError,
    WindowFeatureExtractor,
    feature_names_for,
)
from app.schemas.events import (
    DataCategory,
    EventType,
    LabelProvenance,
    NormalizedEvent,
    QualityFlag,
)

T0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _event(i: int, *, addressed: bool, label: str = "Benign") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"ev-{'a' if addressed else 'n'}-{i}",
        source_id="src-corpus",
        event_type=EventType.NETWORK_FLOW,
        observed_at=T0 + timedelta(seconds=i),
        data_category=DataCategory.HISTORICAL_IMPORT,
        label=label,
        label_provenance=LabelProvenance.DATASET_GROUND_TRUTH,
        src_ip="192.0.2.10" if addressed else None,
        dst_ip="198.51.100.4" if addressed else None,
        dst_port=443,
        protocol="TCP",
        packets=6,
        bytes_total=720,
        duration=0.5,
        quality_flags=[] if addressed else [QualityFlag.SOURCE_LIMITED],
    )


def _stream(n: int, *, addressed: bool) -> list[NormalizedEvent]:
    """A span long enough to window, with attacks late enough to label."""
    events = [_event(i, addressed=addressed) for i in range(n)]
    for i in range(n - 40, n - 10):
        events[i] = _event(i, addressed=addressed, label="DDoS")
    return events


# ──────────────────────────────────────────────────────────────────
# The schema itself
# ──────────────────────────────────────────────────────────────────


def test_the_addressless_schema_omits_exactly_the_two_address_features():
    assert set(FEATURE_NAMES) - set(ADDRESSLESS_FEATURE_NAMES) == set(
        ADDRESS_DEPENDENT_FEATURES
    )
    assert len(ADDRESSLESS_FEATURE_NAMES) == len(FEATURE_NAMES) - 2
    # Order of the surviving features is preserved, so a column index
    # means the same thing in both schemas up to the removal.
    assert ADDRESSLESS_FEATURE_NAMES == [
        n for n in FEATURE_NAMES if n not in ADDRESS_DEPENDENT_FEATURES
    ]


def test_the_two_schemas_have_different_names():
    """A result under one is not comparable with a result under the other."""
    assert FEATURE_SCHEMA_FULL != FEATURE_SCHEMA_ADDRESSLESS
    assert len(feature_names_for(FEATURE_SCHEMA_FULL)) == 12
    assert len(feature_names_for(FEATURE_SCHEMA_ADDRESSLESS)) == 10


# ──────────────────────────────────────────────────────────────────
# An absent address is never a zero
# ──────────────────────────────────────────────────────────────────


def test_address_less_events_drop_the_columns_rather_than_reporting_zero():
    """
    The defect this exists to prevent: `len(set()) == 0` reported as
    "zero distinct source addresses observed", which is a measurement
    nobody took.
    """
    extractor = WindowFeatureExtractor()
    X, y, ts = extractor.build_dataset_instances(_stream(400, addressed=False))

    assert len(X) > 0
    assert extractor.feature_schema == FEATURE_SCHEMA_ADDRESSLESS
    assert X.shape[1] == 10, "the address columns are still present"

    names = feature_names_for(extractor.feature_schema)
    assert "distinct_src_ips" not in names
    assert "distinct_dst_ips" not in names


def test_addressed_events_keep_the_full_schema():
    extractor = WindowFeatureExtractor()
    X, _, _ = extractor.build_dataset_instances(_stream(400, addressed=True))

    assert extractor.feature_schema == FEATURE_SCHEMA_FULL
    assert X.shape[1] == 12
    # And the address counts are real measurements, not zeroes.
    src_col = FEATURE_NAMES.index("distinct_src_ips")
    assert X[:, src_col].max() >= 1


def test_a_mixture_is_refused_not_undercounted():
    """
    Counting distinct addresses over a mixture undercounts by exactly the
    address-less share, and nothing in the number would show it.
    """
    mixed = _stream(200, addressed=True) + [
        _event(1000 + i, addressed=False) for i in range(200)
    ]
    extractor = WindowFeatureExtractor()

    with pytest.raises(MixedAddressAvailabilityError) as exc:
        extractor.build_dataset_instances(mixed)

    assert "undercount" in str(exc.value)


# ──────────────────────────────────────────────────────────────────
# The schema travels with the result
# ──────────────────────────────────────────────────────────────────


def test_the_windowing_report_names_the_schema_it_used():
    extractor = WindowFeatureExtractor()
    extractor.build_dataset_instances(_stream(400, addressed=False))
    report = extractor.last_windowing_report

    assert report is not None
    assert report.feature_schema == FEATURE_SCHEMA_ADDRESSLESS
    assert report.feature_names == ADDRESSLESS_FEATURE_NAMES
    assert any("OMITTED" in n for n in report.notes), (
        "a narrowed schema must be stated, not inferred from a column count"
    )


def test_a_full_schema_run_says_so_without_a_warning_note():
    extractor = WindowFeatureExtractor()
    extractor.build_dataset_instances(_stream(400, addressed=True))
    report = extractor.last_windowing_report

    assert report.feature_schema == FEATURE_SCHEMA_FULL
    assert report.feature_names == FEATURE_NAMES
    assert not any("OMITTED" in n for n in report.notes)


def test_the_two_schemas_produce_different_width_matrices_from_the_same_span():
    """Guards against a silent widening or narrowing going unnoticed."""
    full = WindowFeatureExtractor()
    Xf, _, _ = full.build_dataset_instances(_stream(400, addressed=True))

    reduced = WindowFeatureExtractor()
    Xr, _, _ = reduced.build_dataset_instances(_stream(400, addressed=False))

    assert Xf.shape[1] - Xr.shape[1] == 2
    assert Xf.shape[0] == Xr.shape[0], "the same span must yield the same windows"

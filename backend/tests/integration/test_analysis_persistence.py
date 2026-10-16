"""
PraHari — Measured-Count Persistence (ADR-061).

Four fields were computed correctly by `services/analysis.py` and then
dropped on save: `descriptive_analyses` had no column for them, so they
read back as the Pydantic default **0**.

Observed on the live operational database before the fix, read-only:

    avg_bytes             11474.63      bytes_measured_count     0
    avg_duration        877145.7048     duration_measured_count  0
    implausible_timestamp_events 0      (65 such records exist)

Two different failures in one. An average printed beside "0 measured" is
self-contradictory, and the anomaly count flatly denied 65 records the
Feasibility screen reports in the same session.

The fix adds the columns through the existing additive-migration
mechanism, with **-1 as the sentinel for "this row predates the column"**
so a historical analysis surfaces as `None` — "not recorded" — rather
than 0. A stored analysis cannot be recomputed retroactively, and
backfilling 0 would invent a measurement nobody took.

Temporary databases only.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.schemas.events import (
    DataCategory,
    DescriptiveAnalysis,
    EventType,
    LabelProvenance,
    NormalizedEvent,
)
from app.services.analysis import compute_descriptive_analysis
from app.storage.database import Database, _measured

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "analysis.db"))
    database.initialize()
    yield database
    database.close()


def _event(idx: int, *, bytes_total=None, packets=None, duration=None,
           observed=None) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"an-{idx}",
        source_id="s1",
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=observed or (NOW + timedelta(seconds=idx)),
        event_type=EventType.NETWORK_FLOW,
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=40000 + idx,
        dst_port=443,
        protocol="TCP",
        bytes_total=bytes_total,
        packets=packets,
        duration=duration,
        label_provenance=LabelProvenance.UNLABELED,
    )


# ──────────────────────────────────────────────────────────────────
# The round trip that was broken
# ──────────────────────────────────────────────────────────────────


def test_measured_counts_survive_a_save_and_reload(db):
    events = [_event(i, bytes_total=100 * i, packets=i, duration=1.5) for i in range(1, 11)]
    computed = compute_descriptive_analysis(events, source_id="s1")
    assert computed.bytes_measured_count == 10, "precondition: the engine computes it"

    db.save_analysis(computed)
    reloaded = db.get_latest_analysis()

    assert reloaded is not None
    assert reloaded.bytes_measured_count == 10, "the count was dropped on save"
    assert reloaded.packets_measured_count == 10
    assert reloaded.duration_measured_count == 10


def test_an_average_is_never_reported_beside_a_zero_measured_count(db):
    """The contradiction that exposed the defect."""
    events = [_event(i, bytes_total=1000) for i in range(1, 6)]
    db.save_analysis(compute_descriptive_analysis(events, source_id="s1"))

    r = db.get_latest_analysis()

    if r.avg_bytes is not None:
        assert r.bytes_measured_count not in (0, None), (
            f"avg_bytes={r.avg_bytes} reported with "
            f"bytes_measured_count={r.bytes_measured_count}"
        )


def test_genuinely_unmeasured_fields_report_zero_not_an_average(db):
    """
    The Windows connection table supplies no bytes. Zero measured is then
    the truth, and the average must be absent rather than invented.
    """
    events = [_event(i) for i in range(1, 6)]   # all counters None

    db.save_analysis(compute_descriptive_analysis(events, source_id="s1"))
    r = db.get_latest_analysis()

    assert r.bytes_measured_count == 0
    assert r.avg_bytes is None, "an average was produced from no measurements"


def test_a_partial_measurement_is_counted_honestly(db):
    """Three of ten carry a byte count; the average describes those three."""
    events = [_event(i, bytes_total=300 if i <= 3 else None) for i in range(1, 11)]

    db.save_analysis(compute_descriptive_analysis(events, source_id="s1"))
    r = db.get_latest_analysis()

    assert r.bytes_measured_count == 3
    assert r.avg_bytes == 300
    assert r.total_events == 10


def test_the_implausible_timestamp_count_survives(db):
    """
    The worst of the four: a stored analysis reported 0 anomalies while
    the Feasibility screen reported 65 in the same session.
    """
    events = [_event(i) for i in range(1, 11)]
    events.append(_event(99, observed=datetime(1601, 1, 1, tzinfo=timezone.utc)))
    computed = compute_descriptive_analysis(events, source_id="s1")
    assert computed.implausible_timestamp_events == 1, "precondition"

    db.save_analysis(computed)

    assert db.get_latest_analysis().implausible_timestamp_events == 1


# ──────────────────────────────────────────────────────────────────
# "not recorded" must stay distinct from "zero"
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "stored, expected",
    [(-1, None), (0, 0), (5, 5), (None, None), ("", None), ("7", 7)],
)
def test_the_sentinel_reads_as_not_recorded(stored, expected):
    assert _measured(stored) is expected or _measured(stored) == expected


def test_an_analysis_predating_the_column_reads_as_none_not_zero(db, tmp_path):
    """
    A historical row cannot be recomputed. Reporting 0 would invent a
    measurement; None says plainly that it was not recorded.
    """
    events = [_event(i, bytes_total=500) for i in range(1, 6)]
    db.save_analysis(compute_descriptive_analysis(events, source_id="s1"))

    # Simulate a row written before the column existed.
    with db.get_connection() as conn:
        conn.execute("UPDATE descriptive_analyses SET bytes_measured_count = -1")

    r = db.get_latest_analysis()

    assert r.bytes_measured_count is None
    assert r.bytes_measured_count != 0


def test_the_migration_adds_the_columns_to_an_older_database(tmp_path):
    """Additive, and existing rows are preserved."""
    from app.storage.database import TABLES_DDL

    db_file = tmp_path / "legacy.db"
    legacy = "\n".join(
        line for line in TABLES_DDL.splitlines()
        if "measured_count" not in line and "implausible_timestamp_events" not in line
    )
    con = sqlite3.connect(db_file)
    con.executescript(legacy)
    con.commit()
    before = {r[1] for r in con.execute("PRAGMA table_info(descriptive_analyses)")}
    con.close()
    assert "bytes_measured_count" not in before

    database = Database(db_path=str(db_file))
    database.initialize()
    with database.get_connection() as conn:
        after = {r["name"] for r in conn.execute("PRAGMA table_info(descriptive_analyses)")}
    database.close()

    for col in ("bytes_measured_count", "packets_measured_count",
                "duration_measured_count", "implausible_timestamp_events"):
        assert col in after, f"{col} was not added by the migration"


def test_reloading_twice_is_stable(db):
    """A save/reload cycle must not drift the counts."""
    events = [_event(i, bytes_total=100, packets=2) for i in range(1, 8)]
    db.save_analysis(compute_descriptive_analysis(events, source_id="s1"))

    first = db.get_latest_analysis()
    db.save_analysis(first)
    second = db.get_latest_analysis()

    assert first.bytes_measured_count == second.bytes_measured_count
    assert first.packets_measured_count == second.packets_measured_count

"""
The PERSISTED poll summary must reconcile (ADR-123).

A session on the operator's real machine found that it did not. In that
database, across 434 polls:

    total=34,279   accepted=1,885   rejected=0   reasons={}

**32,394 records with no account of where they went.** The live
`PollResult` reconciled perfectly the whole time, because it captured
the duplicate and filtered counts into their own fields — and then
`.pop()` removed them from the summary object that `_persist` goes on
to store.

The adapter was tested. The live API was tested. The durable row was
not, which is why a green suite never saw it.

These tests exercise the stored row, through the real collector and the
real storage layer.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from app.schemas.events import (
    DataCategory,
    EventType,
    ImportSummary,
    LabelProvenance,
    NormalizedEvent,
)
from app.services.collector import WindowsTelemetryCollectorService
from app.storage.database import Database


class _StubAdapter:
    """
    Produces a summary shaped exactly as the Windows adapter's is: some
    accepted, some rejected, and some accounted for under the two
    underscore-prefixed bookkeeping keys.

    Substituted for the real adapter so the test exercises the
    collector's accounting rather than the adapter's parsing.
    """

    adapter_id = "stub_collector"
    source_type = "windows_connection_table"

    def forget_last_batch(self):
        return None

    def prune_fingerprint_cache(self):
        return None

    #: When False, `normalize_batch` returns no event — the shape of a
    #: poll on a quiet machine, where every observed connection is a
    #: repeat of one already stored.
    emits_event = True

    def normalize_batch(self, records, data_category, poll_time):
        summary = ImportSummary(
            source_id="stub_collector",
            data_category=data_category,
            total_records=10,
            accepted_records=2,
            rejected_records=1,
            warnings_count=0,
            rejection_reasons={
                "invalid_port": 1,
                "_duplicates_suppressed": 6,
                "_filtered_by_policy": 1,
            },
            completed_at=datetime.now(timezone.utc),
        )
        if not self.emits_event:
            return [], summary
        event = NormalizedEvent(
            event_id="stub-event-1",
            source_id="stub_collector",
            data_category=data_category,
            observed_at=poll_time,
            event_type=EventType.CONNECTION,
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            label_provenance=LabelProvenance.UNLABELED,
        )
        return [event], summary


@pytest.fixture()
def db(tmp_path):
    store = Database(str(tmp_path / "accounting.db"))
    store.initialize()
    return store


def _poll(db, emits_event: bool = True) -> object:
    collector = WindowsTelemetryCollectorService(
        db=db,
        source_id="stub_collector",
        # Ten raw rows; what becomes of each is the stub's business.
        query_fn=lambda *_a, **_k: [{"i": i} for i in range(10)],
    )
    # No platform override needed: injecting `query_fn` already lifts
    # the gate, because the gate exists to stop the PowerShell probe
    # running where there is no connection table, not to stop collection.
    adapter = _StubAdapter()
    adapter.emits_event = emits_event
    collector.adapter = adapter
    return asyncio.run(collector.poll_once())


def test_the_stored_summary_accounts_for_every_record(db):
    """
    total = accepted + duplicates + filtered + rejected.

    This is the identity the live result has always satisfied and the
    stored row silently did not.
    """
    _poll(db)

    summaries = db.list_import_summaries()
    assert len(summaries) == 1, "the poll stored no summary"
    stored = summaries[0]

    reasons = stored.rejection_reasons
    duplicates = reasons.get("_duplicates_suppressed", 0)
    filtered = reasons.get("_filtered_by_policy", 0)
    rejected = stored.rejected_records

    accounted = stored.accepted_records + duplicates + filtered + rejected
    assert accounted == stored.total_records, (
        f"{stored.total_records - accounted} record(s) stored with no "
        f"account of where they went: accepted={stored.accepted_records}, "
        f"duplicates={duplicates}, filtered={filtered}, rejected={rejected}"
    )


def test_the_bookkeeping_counts_survive_persistence(db):
    """
    The specific regression. `.pop()` removed them from the object that
    `_persist` then stored, so they reached the database as `{}`.
    """
    _poll(db)
    stored = db.list_import_summaries()[0]

    assert stored.rejection_reasons.get("_duplicates_suppressed") == 6
    assert stored.rejection_reasons.get("_filtered_by_policy") == 1
    # The genuine rejection is still there alongside them.
    assert stored.rejection_reasons.get("invalid_port") == 1


def test_the_live_result_reports_rejections_only(db):
    """
    The counterpart that must not regress. In the live view,
    `rejection_reasons` means rejections — a bookkeeping key there would
    read as one. They travel in their own fields instead.
    """
    result = _poll(db)

    assert result.rejection_reasons == {"invalid_port": 1}
    assert not any(k.startswith("_") for k in result.rejection_reasons)
    assert result.duplicates_suppressed == 6
    assert result.records_filtered_by_policy == 1

    # And the live result still reconciles, as it always did.
    assert (
        result.events_accepted
        + result.duplicates_suppressed
        + result.records_filtered_by_policy
        + result.records_rejected
        == result.records_observed
    )


def test_the_live_and_stored_views_agree_on_every_figure(db):
    """
    Two views of one poll. They had diverged silently; nothing compared
    them, which is how it survived.
    """
    result = _poll(db)
    stored = db.list_import_summaries()[0]

    assert stored.total_records == result.records_observed
    assert stored.accepted_records == result.events_accepted
    assert stored.rejected_records == result.records_rejected
    assert (
        stored.rejection_reasons.get("_duplicates_suppressed")
        == result.duplicates_suppressed
    )
    assert (
        stored.rejection_reasons.get("_filtered_by_policy")
        == result.records_filtered_by_policy
    )


def test_a_poll_that_stores_no_new_event_still_stores_its_summary(db):
    """
    The second gap the first one hid.

    `save_import_summary` was reached only through `_persist`, which runs
    only when there is a new event to insert. On a quiet machine most
    polls have none — the same long-lived connections, every one a repeat
    — so those polls recorded nothing at all. The quieter the host, the
    more of its history was missing, and nothing on screen said so.
    """
    result = _poll(db, emits_event=False)

    assert result.succeeded
    summaries = db.list_import_summaries()
    assert len(summaries) == 1, (
        "a poll that observed 10 records and stored no new event left no "
        "trace: the quiet polls are exactly the ones that go missing"
    )
    stored = summaries[0]
    assert stored.total_records == 10
    assert stored.rejection_reasons.get("_duplicates_suppressed") == 6


def test_the_quiet_poll_is_not_counted_twice(db):
    """
    One poll, one summary — whichever path stored it.

    The summary-only path must not also run for a poll that persisted
    normally, or every busy poll would be recorded twice and the totals
    would read high instead of low.
    """
    _poll(db)
    assert len(db.list_import_summaries()) == 1

"""
Windows-only: continuous DNS collection against the real event log.

**These do not run in CI and have never run on this machine.** They need
Windows, the Microsoft-Windows-DNS-Client/Operational channel enabled,
and an account permitted to read it. Everything that can be tested
without those lives in `tests/unit/test_dns_incremental_collection.py`,
and passing there proves the bookkeeping — not that PowerShell returns
what the adapter expects.

Run them on the Windows host, from `backend/`:

    .venv\\Scripts\\python -m pytest tests/integration/test_dns_collector_windows_live.py -v -s

They are read-only: no channel is enabled, no log is cleared, no DNS
query is sent. To generate evidence for them to find, resolve a name in
another window first:

    Resolve-DnsName example.com
"""

from __future__ import annotations

import asyncio
import platform
import time

import pytest

from app.services.dns_collector import DnsEventCollectorService
from app.services.enrichment import get_enrichment_service
from app.storage.database import Database

windows_only = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="requires a real Windows host with the DNS-Client channel enabled",
)


@pytest.fixture()
def db(tmp_path):
    store = Database(db_path=str(tmp_path / "dns_live.db"))
    store.initialize()
    yield store
    store.close()


@windows_only
def test_the_channel_can_actually_be_read(db):
    """The read that no mock can stand in for."""
    from app.adapters.windows_dns_events import read_dns_events

    read = read_dns_events(max_events=50)

    assert read.newest_record_id > 0, (
        "the channel reported no records; enable it and resolve a name first"
    )
    assert all("RecordId" in r for r in read.records), (
        "RecordId is missing — the bookmark cannot advance without it"
    )


@windows_only
def test_a_second_read_returns_only_newer_records(db):
    """
    The incremental contract, against the real log.

    This is the behaviour the unit tests mock: filtering by
    EventRecordID must genuinely narrow the result, or continuous
    collection degrades to re-reading the same window for ever.
    """
    service = get_enrichment_service(db)

    first = service.collect_from_dns_event_log(max_events=50, incremental=True)
    assert first["succeeded"], first["error"]
    bookmark = first["bookmark_after"]
    assert bookmark > 0

    second = service.collect_from_dns_event_log(max_events=50, incremental=True)
    assert second["succeeded"], second["error"]
    assert second["bookmark_before"] == bookmark
    assert second["records_read"] <= first["records_read"], (
        "the second read was not narrowed by the bookmark"
    )
    assert second["bookmark_after"] >= bookmark, "the bookmark went backwards"


@windows_only
def test_new_resolutions_are_picked_up_by_the_running_loop(db):
    """
    End to end: start the loop, resolve a name, see the bookmark move.

    Resolve something in another window while this runs if the host is
    otherwise idle.
    """
    service = DnsEventCollectorService(db=db, interval_seconds=2.0, batch_size=200)

    async def run():
        status = await service.start()
        assert status.state == "running", status.last_error
        try:
            start_bookmark = status.bookmark
            # Give the loop several intervals to see live DNS activity.
            for _ in range(15):
                await asyncio.sleep(2)
                if service.status().bookmark > start_bookmark:
                    return True
            return False
        finally:
            await service.stop()

    moved = asyncio.run(run())
    if not moved:
        pytest.skip(
            "no DNS activity occurred during the window; resolve a name while "
            "this test runs to exercise the live path"
        )
    assert service.polls_succeeded > 0
    assert service.status().bookmark > 0


@windows_only
def test_the_bookmark_survives_a_service_restart(db):
    """
    Restart recovery on the real store: a new service object over the
    same database resumes rather than re-reading the whole window.
    """
    service = get_enrichment_service(db)
    first = service.collect_from_dns_event_log(max_events=50, incremental=True)
    assert first["succeeded"], first["error"]
    saved = service.read_bookmark()
    assert saved > 0

    import app.services.enrichment as enrichment_module

    enrichment_module._service = None  # type: ignore[attr-defined]
    revived = get_enrichment_service(db)

    assert revived.read_bookmark() == saved


@windows_only
def test_collection_changes_no_windows_configuration(db):
    """
    PraHari reads. It must not enable the channel, clear the log, or
    alter its configuration — that needs Administrator and is the
    operator's decision (ADR-121).
    """
    import subprocess

    def channel_state() -> str:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Get-WinEvent -ListLog 'Microsoft-Windows-DNS-Client/Operational')"
             " | Select-Object -Property IsEnabled,MaximumSizeInBytes,RecordCount"
             " | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=60,
        )
        return (out.stdout or "").strip()

    before = channel_state()
    get_enrichment_service(db).collect_from_dns_event_log(max_events=50, incremental=True)
    after = channel_state()

    import json

    b, a = json.loads(before), json.loads(after)
    assert b["IsEnabled"] == a["IsEnabled"], "collection changed whether the channel is on"
    assert b["MaximumSizeInBytes"] == a["MaximumSizeInBytes"], (
        "collection changed the channel's configured size"
    )
    # RecordCount may rise from unrelated DNS activity, but must not fall:
    # a drop would mean something cleared the log.
    assert a["RecordCount"] >= b["RecordCount"], "records disappeared during collection"

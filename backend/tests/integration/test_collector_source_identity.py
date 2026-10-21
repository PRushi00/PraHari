"""
PraHari — Per-host collector identity (ADR-099).

`MULTI_SYSTEM_CAPABILITY.md` records "Multiple endpoint identities" as
PARTIAL, and offers two ways out: a per-source collector registry, or
"accept that each endpoint runs its own agent". The second was already
the deployment story — and it did not work, because the collector's
source id was the constant `windows_local_host` with no configuration,
API parameter or environment variable able to change it.

So every Windows host filed its telemetry under one identity. That is
not merely ambiguous labelling: `WindowsConnectionAdapter.fingerprint`
hashes the adapter id as its FIRST component, so two hosts sharing the
id produce the same `event_id` for a connection matching on the rest of
the tuple, and `INSERT OR IGNORE` keeps whichever arrived first. One
host's observation silently replaces the other's.

These pin the resolution:

* the id is configurable, and unset still means the historical default,
  so an existing installation keeps its source and its stored events;
* a configured id actually reaches event identity, which is the whole
  point — two hosts stop colliding;
* a bad id is refused at startup rather than at the first status poll;
* the reservation guard (ADR-090) covers the CONFIGURED id, not just the
  constant, so a custom-id deployment does not reopen the window where
  external telemetry could be filed into the live host source.
"""

from __future__ import annotations

import pytest

from app.core.config import AppConfig, InvalidCollectorSourceId
from app.services.collector import DEFAULT_SOURCE_ID

HOST_A = "laptop-a"
HOST_B = "laptop-b"

# One connection, observed identically on two different machines: same
# private address range, same ephemeral port, same destination, same pid.
# Contrived, but nothing prevents it, and the collision is silent.
SHARED_RECORD = {
    "protocol": "TCP",
    "local_address": "192.168.1.10",
    "local_port": 51000,
    "remote_address": "93.184.216.34",
    "remote_port": 443,
    "owning_pid": 4242,
    "creation_time": "2026-10-21T09:00:00Z",
}


def _adapter(source_id: str):
    from app.adapters.windows_telemetry import WindowsConnectionAdapter

    return WindowsConnectionAdapter(adapter_id=source_id)


# ──────────────────────────────────────────────────────────────────
# Resolution
# ──────────────────────────────────────────────────────────────────


def test_an_unset_id_keeps_the_historical_default():
    """An upgrade must not orphan the events an installation already has."""
    assert AppConfig().resolved_collector_source_id() == DEFAULT_SOURCE_ID
    assert AppConfig(collector_source_id="   ").resolved_collector_source_id() == (
        DEFAULT_SOURCE_ID
    )


def test_a_configured_id_is_used():
    config = AppConfig(collector_source_id=HOST_A)
    assert config.resolved_collector_source_id() == HOST_A


@pytest.mark.parametrize(
    "bad",
    [
        "Laptop-A",  # uppercase: the same host two ways in URLs and logs
        "9lives",  # leading digit
        "_leading",  # leading underscore
        "has space",
        "has.dot",
        "has/slash",  # would change the shape of a source URL
        "x" * 65,
    ],
)
def test_an_unusable_id_is_refused(bad: str):
    with pytest.raises(InvalidCollectorSourceId):
        AppConfig(collector_source_id=bad).resolved_collector_source_id()


def test_the_udp_observers_id_is_refused():
    """
    Two in-process producers on one source would leave the reservation
    guard unable to name which of them owns it.
    """
    from app.api.v1.hostobs import UDP_SOURCE_ID

    with pytest.raises(InvalidCollectorSourceId) as exc:
        AppConfig(collector_source_id=UDP_SOURCE_ID).resolved_collector_source_id()

    assert "reserved" in str(exc.value)


# ──────────────────────────────────────────────────────────────────
# The point of it: two hosts stop colliding
# ──────────────────────────────────────────────────────────────────


def test_two_hosts_on_the_default_id_produce_the_same_event_id():
    """
    The defect, pinned so a regression is visible rather than inferred.
    This is why the id must be set before two hosts' data is merged.
    """
    a = _adapter(DEFAULT_SOURCE_ID)
    b = _adapter(DEFAULT_SOURCE_ID)

    assert a.event_id_for(SHARED_RECORD) == b.event_id_for(SHARED_RECORD)


def test_two_hosts_with_distinct_ids_produce_distinct_event_ids():
    a = _adapter(HOST_A)
    b = _adapter(HOST_B)

    assert a.event_id_for(SHARED_RECORD) != b.event_id_for(SHARED_RECORD)


def test_a_configured_id_reaches_event_identity(monkeypatch, tmp_path):
    """
    Configuration that never arrives at the adapter would be decoration.
    The collector is built through its real factory.
    """
    from app.api import deps
    from app.core import config as config_module
    from app.services import collector as collector_module

    monkeypatch.setenv("PRAHARI_COLLECTOR_SOURCE_ID", HOST_A)
    monkeypatch.setattr(
        config_module, "get_config", lambda: AppConfig(collector_source_id=HOST_A)
    )

    db = deps.Database(str(tmp_path / "ident.db"))
    db.initialize()
    collector_module.reset_collector(None)
    try:
        collector = collector_module.get_collector(db)
        assert collector.source_id == HOST_A
        assert collector.status().source_id == HOST_A
        assert collector.adapter.event_id_for(SHARED_RECORD) == (
            _adapter(HOST_A).event_id_for(SHARED_RECORD)
        )
    finally:
        collector_module.reset_collector(None)
        db.close()


# ──────────────────────────────────────────────────────────────────
# The reservation guard follows the configured id (ADR-090 + ADR-099)
# ──────────────────────────────────────────────────────────────────


def test_the_reservation_guard_covers_the_configured_id(monkeypatch):
    """
    The collector is built lazily, so between a restart and the first
    status poll the adapter registry is empty. Without this, external
    telemetry could be filed into the live host's own source during that
    window — the defect ADR-090 closed, reopened for a custom id.
    """
    from app.adapters.base import get_adapter_registry
    from app.api import auth
    from app.core import config as config_module

    monkeypatch.setattr(
        config_module, "get_config", lambda: AppConfig(collector_source_id=HOST_A)
    )
    # The registry is process-wide and another test may have left this
    # host's adapter in it. Emptying it IS the post-restart state, and
    # without it this passes through the registry layer and proves
    # nothing about the reserved layer.
    get_adapter_registry().clear()

    assert auth.local_producer_owning(HOST_A) is not None
    assert auth.local_producer_owning(DEFAULT_SOURCE_ID) is not None
    assert auth.local_producer_owning("some-remote-sensor") is None


def test_a_misconfigured_id_still_protects_the_default(monkeypatch):
    """A configuration error must not leave the default unguarded."""
    from app.api import auth
    from app.core import config as config_module

    monkeypatch.setattr(
        config_module, "get_config", lambda: AppConfig(collector_source_id="Bad Id")
    )

    assert auth.local_producer_owning(DEFAULT_SOURCE_ID) is not None

"""
Tests for domain enrichment.

Attribution is an inference, so the tests check the *evidence and
confidence* as much as the hostname: a correct name with overstated
confidence is a defect, and so is naming an address owner as though it were
the site the user visited.
"""

import sys
from datetime import datetime, timedelta, timezone

import pytest

from app.schemas.events import (
    AttributionConfidence,
    DataCategory,
    DomainAttributionMethod,
    EventType,
    NormalizedEvent,
)
from app.services.enrichment import (
    diagnose_dns_visibility,
    CACHE_EMPTY_DIAGNOSIS,
    STALE_AFTER_SECONDS,
    DnsCacheUnavailable,
    DomainEnrichmentService,
    _is_private,
)
from app.storage.database import Database

NOW = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "enrich.db"))
    database.initialize()
    yield database
    database.close()


def _obs(hostname: str, age_seconds: float = 0.0, method: str = "dns_cache_observation") -> dict:
    return {
        "hostname": hostname,
        "observed_at": (NOW - timedelta(seconds=age_seconds)).isoformat(),
        "method": method,
        "ttl_seconds": 300,
    }


def _event(dst_ip: str = "93.184.216.34", **kw) -> NormalizedEvent:
    defaults = dict(
        source_id="windows_local_host",
        data_category=DataCategory.LIVE_TELEMETRY,
        observed_at=NOW,
        event_type=EventType.CONNECTION,
        src_ip="192.168.1.5",
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=443,
        protocol="TCP",
    )
    defaults.update(kw)
    return NormalizedEvent(**defaults)


# ──────────────────────────────────────────────────────────────────
# Attribution cases
# ──────────────────────────────────────────────────────────────────


def test_known_single_recent_resolution_is_high_confidence(db):
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    result = svc.attribute_ip(
        "93.184.216.34", observations=[_obs("example.com", 30)], reference_time=NOW
    )

    assert result.hostname == "example.com"
    assert result.confidence == AttributionConfidence.HIGH
    assert result.method == DomainAttributionMethod.DNS_CACHE_OBSERVATION
    assert result.identifies_requested_host is True
    assert result.attribution_kind == "requested_host"
    assert result.candidate_count == 1
    # Even a confident attribution states that it is an inference.
    assert any("inferred" in l.lower() for l in result.limitations)


def test_unknown_ip_is_reported_unknown_not_guessed(db):
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    result = svc.attribute_ip("198.51.100.77", observations=[], reference_time=NOW)

    assert result.hostname is None
    assert result.is_attributed is False
    assert result.confidence == AttributionConfidence.NONE
    assert result.method == DomainAttributionMethod.NONE
    reason = " ".join(result.limitations).lower()
    assert "no local dns observation" in reason
    # The honest possibilities are named rather than left implicit.
    assert "encrypted dns" in reason


def test_ambiguous_shared_ip_is_capped_at_medium_confidence(db):
    """Many hostnames on one address (CDN) cannot yield a confident answer."""
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    observations = [
        _obs("site-a.example.com", 10),
        _obs("site-b.example.org", 20),
        _obs("site-c.example.net", 30),
    ]
    result = svc.attribute_ip("104.20.1.1", observations=observations, reference_time=NOW)

    assert result.confidence == AttributionConfidence.MEDIUM
    assert result.candidate_count == 3
    assert set(result.candidate_hostnames) == {
        "site-a.example.com", "site-b.example.org", "site-c.example.net",
    }
    assert any("cdn" in l.lower() or "shared" in l.lower() for l in result.limitations)


def test_stale_evidence_is_demoted_to_low_confidence(db):
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    result = svc.attribute_ip(
        "93.184.216.34",
        observations=[_obs("example.com", STALE_AFTER_SECONDS + 600)],
        reference_time=NOW,
    )

    assert result.hostname == "example.com"
    assert result.confidence == AttributionConfidence.LOW
    assert result.evidence_age_seconds > STALE_AFTER_SECONDS
    assert any("old" in l.lower() or "rotate" in l.lower() for l in result.limitations)


def test_most_recent_observation_wins(db):
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    result = svc.attribute_ip(
        "93.184.216.34",
        observations=[_obs("old.example.com", 5000), _obs("new.example.com", 10)],
        reference_time=NOW,
    )
    assert result.hostname == "new.example.com"


def test_attribution_reports_the_method_that_produced_it(db):
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    result = svc.attribute_ip(
        "93.184.216.34",
        observations=[_obs("logged.example.com", 10, method="dns_query_log")],
        reference_time=NOW,
    )
    assert result.method == DomainAttributionMethod.DNS_QUERY_LOG


def test_missing_destination_ip_is_handled(db):
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    result = svc.attribute_ip(None)
    assert result.hostname is None
    assert result.confidence == AttributionConfidence.NONE


def test_unparseable_observation_timestamps_do_not_crash(db):
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    result = svc.attribute_ip(
        "93.184.216.34",
        observations=[{"hostname": "x.example.com", "observed_at": "not-a-date", "method": "dns_cache_observation"}],
        reference_time=NOW,
    )
    assert result.hostname is None


# ──────────────────────────────────────────────────────────────────
# Source-reported hostnames outrank inference
# ──────────────────────────────────────────────────────────────────


def test_application_layer_hostname_outranks_dns_inference(db):
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    db.record_dns_observations([
        {
            "ip_address": "93.184.216.34",
            "hostname": "inferred.example.net",
            "observed_at": NOW.isoformat(),
            "method": "dns_cache_observation",
        }
    ])

    event = _event(dst_hostname="reported.example.com")
    results = svc.attribute_events([event])
    attribution = results[event.event_id]

    assert attribution.hostname == "reported.example.com"
    assert attribution.method == DomainAttributionMethod.APPLICATION_LAYER_REPORTED
    assert attribution.confidence == AttributionConfidence.HIGH
    assert attribution.identifies_requested_host is True


# ──────────────────────────────────────────────────────────────────
# Reverse DNS: infrastructure owner, never the requested host
# ──────────────────────────────────────────────────────────────────


def test_reverse_dns_is_never_presented_as_the_requested_host(db, monkeypatch):
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    monkeypatch.setattr(
        "socket.gethostbyaddr",
        lambda ip: ("server-1-2-3.edge.cloudfront.net", [], [ip]),
    )

    result = svc.reverse_lookup("198.51.100.9")

    assert result.hostname == "server-1-2-3.edge.cloudfront.net"
    assert result.method == DomainAttributionMethod.REVERSE_DNS
    assert result.confidence == AttributionConfidence.LOW
    # The decisive assertions: this is NOT the site the user visited.
    assert result.identifies_requested_host is False
    assert result.attribution_kind == "infrastructure_owner"
    assert any("not the" in l.lower() and "requested" in l.lower() for l in result.limitations)


def test_reverse_dns_absent_ptr_is_reported_unknown(db, monkeypatch):
    import socket as _socket

    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    monkeypatch.setattr(
        "socket.gethostbyaddr",
        lambda ip: (_ for _ in ()).throw(_socket.herror("no PTR")),
    )
    result = svc.reverse_lookup("104.20.23.154")
    assert result.hostname is None
    assert result.confidence == AttributionConfidence.NONE


def test_reverse_dns_is_opt_in_and_skipped_by_default(db, monkeypatch):
    called = {"n": 0}

    def _count(ip):
        called["n"] += 1
        return ("ptr.example.net", [], [ip])

    monkeypatch.setattr("socket.gethostbyaddr", _count)
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])

    # 93.184.216.34 is globally routable, so the private-address guard does
    # not apply and only the opt-in flag decides.
    svc.attribute_events([_event("93.184.216.34")])  # allow_reverse_dns defaults False
    assert called["n"] == 0

    svc.attribute_events([_event("93.184.216.34")], allow_reverse_dns=True)
    assert called["n"] == 1


def test_reverse_dns_not_attempted_for_private_addresses(db, monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(
        "socket.gethostbyaddr",
        lambda ip: (called.__setitem__("n", called["n"] + 1), ("x", [], [ip]))[1],
    )
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    svc.attribute_events([_event("192.168.1.20")], allow_reverse_dns=True)
    assert called["n"] == 0


def test_private_address_detection():
    # Documentation ranges (RFC 5737) are non-routable and must not be
    # subjected to PTR lookups either.
    assert _is_private("203.0.113.9") is True
    assert _is_private("198.51.100.1") is True
    assert _is_private("127.0.0.1") is True
    assert _is_private("192.168.1.1") is True
    assert _is_private("10.0.0.1") is True
    assert _is_private("169.254.1.1") is True
    assert _is_private("8.8.8.8") is False
    assert _is_private("not-an-ip") is True


def test_infrastructure_names_are_excluded_from_analytics_aggregation(db, monkeypatch):
    """
    A PTR name must not be folded into "top domains" — that would imply the
    user visited a CDN edge server.
    """
    monkeypatch.setattr(
        "socket.gethostbyaddr", lambda ip: ("edge.cloudfront.net", [], [ip])
    )
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    assert svc.hostname_for_event(_event("93.184.216.34")) is None


def test_confident_dns_hostname_is_used_for_aggregation(db):
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    db.record_dns_observations([
        {
            "ip_address": "93.184.216.34",
            "hostname": "example.com",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "method": "dns_cache_observation",
        }
    ])
    assert svc.hostname_for_event(_event("93.184.216.34")) == "example.com"


# ──────────────────────────────────────────────────────────────────
# Cache collection and unavailability
# ──────────────────────────────────────────────────────────────────


def test_refresh_records_address_records_and_skips_others(db):
    records = [
        {"hostname": "example.com", "data": "93.184.216.34", "type": 1, "ttl": 300},
        {"hostname": "ipv6.example.com", "data": "2606:2800:220:1:248:1893:25c8:1946", "type": 28, "ttl": 300},
        {"hostname": "alias.example.com", "data": "example.com", "type": 5, "ttl": 300},  # CNAME
        {"hostname": "", "data": "1.2.3.4", "type": 1, "ttl": 300},                       # no name
    ]
    svc = DomainEnrichmentService(db=db, query_fn=lambda: records)
    result = svc.refresh_from_dns_cache()

    assert result["succeeded"] is True
    assert result["address_records"] == 2
    assert result["skipped_non_address_records"] == 2
    assert result["observations_recorded"] == 2
    assert db.count_dns_observations() == 2


def test_empty_cache_is_diagnosed_not_silently_accepted(db):
    """
    An empty cache must be explained. On hosts using DoH it stays empty
    permanently, and reporting "no domains" would be misleading.
    """
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    result = svc.refresh_from_dns_cache()

    assert result["succeeded"] is True
    assert result["cache_appears_unavailable"] is True
    assert result["diagnosis"] == CACHE_EMPTY_DIAGNOSIS
    assert "encrypted dns" in result["diagnosis"].lower()

    status = svc.status()
    assert status["cache_appears_unavailable"] is True
    assert status["diagnosis"] is not None


def test_cache_failure_is_surfaced_not_swallowed(db):
    def _fail():
        raise DnsCacheUnavailable("simulated cache failure")

    svc = DomainEnrichmentService(db=db, query_fn=_fail)
    result = svc.refresh_from_dns_cache()

    assert result["succeeded"] is False
    assert "simulated cache failure" in result["error"]
    assert svc.status()["last_error"] is not None


def test_observations_accumulate_rather_than_overwrite(db):
    """Conflicting answers must both remain visible as evidence."""
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    for host in ("a.example.com", "b.example.com"):
        db.record_dns_observations([
            {
                "ip_address": "104.20.1.1",
                "hostname": host,
                "observed_at": NOW.isoformat(),
                "method": "dns_cache_observation",
            }
        ])

    stored = db.get_dns_observations_for_ip("104.20.1.1")
    assert {o["hostname"] for o in stored} == {"a.example.com", "b.example.com"}


def test_duplicate_observations_are_not_double_counted(db):
    obs = {
        "ip_address": "93.184.216.34",
        "hostname": "example.com",
        "observed_at": NOW.isoformat(),
        "method": "dns_cache_observation",
    }
    assert db.record_dns_observations([obs]) == 1
    assert db.record_dns_observations([obs]) == 0
    assert db.count_dns_observations() == 1


def test_bulk_lookup_returns_entry_for_every_requested_ip(db):
    db.record_dns_observations([
        {
            "ip_address": "93.184.216.34",
            "hostname": "example.com",
            "observed_at": NOW.isoformat(),
            "method": "dns_cache_observation",
        }
    ])
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    bulk = db.get_dns_observations_for_ips(["93.184.216.34", "198.51.100.1"])

    assert len(bulk["93.184.216.34"]) == 1
    assert bulk["198.51.100.1"] == []


def test_enrichment_never_mutates_the_connection_record(db):
    db.record_dns_observations([
        {
            "ip_address": "93.184.216.34",
            "hostname": "example.com",
            "observed_at": NOW.isoformat(),
            "method": "dns_cache_observation",
        }
    ])
    svc = DomainEnrichmentService(db=db, query_fn=lambda: [])
    event = _event("93.184.216.34")

    svc.attribute_events([event])

    assert event.dst_ip == "93.184.216.34"
    assert event.dst_hostname is None  # inference is returned alongside, not written in


# ──────────────────────────────────────────────────────────────────
# DNS visibility diagnosis
# ──────────────────────────────────────────────────────────────────


def test_diagnosis_explains_an_empty_cache_with_doh_evidence(monkeypatch):
    """
    An empty cache alone does not distinguish "this host resolves names in
    a way PraHari cannot see" from "PraHari failed to read the cache". The
    diagnosis must cite actual resolver configuration.
    """
    import json as _json
    import subprocess as _sp

    payload = {
        "doh_servers": [
            {"server": "8.8.8.8", "template": "https://dns.google/dns-query",
             "auto_upgrade": True},
            {"server": "1.1.1.1", "template": "https://cloudflare-dns.com/dns-query",
             "auto_upgrade": True},
        ],
        "interfaces": [{"interface": "Ethernet", "servers": ["8.8.8.8", "1.1.1.1"]}],
        "cache_entries": 0,
        "dnscache_service": "Running",
    }

    class _Proc:
        returncode = 0
        stdout = _json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(_sp, "run", lambda *a, **k: _Proc())

    diag = diagnose_dns_visibility()

    assert diag["cache_entries"] == 0
    assert diag["doh_auto_upgrade_enabled"] is True
    assert diag["resolvers_with_doh_auto_upgrade"] == ["1.1.1.1", "8.8.8.8"]
    assert diag["dnscache_service"] == "Running"
    # The conclusion must frame this as a source limit, not a failure...
    assert "visibility limit" in diag["conclusion"].lower()
    # ...and must NOT assert a single cause.
    assert "not established" in diag["conclusion"].lower()
    assert any("DNS-over-HTTPS" in c for c in diag["likely_causes"])
    # Elevation is acknowledged as an unexcluded possibility, not asserted.
    assert any("elevation" in c.lower() for c in diag["likely_causes"])


def test_known_doh_table_is_not_treated_as_proof_of_doh_use(monkeypatch):
    """
    Windows ships a table of well-known DoH servers. An entry means the
    address OFFERS DoH — not that this machine used it. Asserting otherwise
    would be an unsupported causal claim.
    """
    import json as _json
    import subprocess as _sp

    class _Proc:
        returncode = 0
        # Listed in the table, but auto-upgrade OFF — the real state of the
        # development host.
        stdout = _json.dumps({
            "doh_servers": [
                {"server": "8.8.8.8", "template": "https://dns.google/dns-query",
                 "auto_upgrade": False},
            ],
            "interfaces": [{"interface": "Ethernet", "servers": ["8.8.8.8"]}],
            "cache_entries": 0,
            "dnscache_service": "Running",
        })
        stderr = ""

    monkeypatch.setattr(_sp, "run", lambda *a, **k: _Proc())
    diag = diagnose_dns_visibility()

    assert diag["doh_auto_upgrade_enabled"] is False
    assert diag["resolvers_with_doh_auto_upgrade"] == []
    assert diag["resolvers_in_known_doh_table"] == ["8.8.8.8"]

    doh_cause = next(c for c in diag["likely_causes"] if "DoH" in c or "DNS-over-HTTPS" in c)
    # It must say the table is not evidence of use.
    assert "not evidence" in doh_cause.lower()
    assert "auto-upgrade is OFF" in doh_cause
    assert "not established" in diag["conclusion"].lower()


def test_diagnosis_reports_a_populated_cache_as_usable(monkeypatch):
    import json as _json
    import subprocess as _sp

    class _Proc:
        returncode = 0
        stdout = _json.dumps({
            "doh_servers": [],
            "interfaces": [{"interface": "Wi-Fi", "servers": ["192.168.1.1"]}],
            "cache_entries": 42,
            "dnscache_service": "Running",
        })
        stderr = ""

    monkeypatch.setattr(_sp, "run", lambda *a, **k: _Proc())

    diag = diagnose_dns_visibility()
    assert diag["cache_entries"] == 42
    assert diag["doh_auto_upgrade_enabled"] is False
    assert "42 cached DNS record(s)" in diag["conclusion"]
    assert diag["likely_causes"] == []


def test_diagnosis_failure_is_reported_not_swallowed(monkeypatch):
    import subprocess as _sp

    def _boom(*a, **k):
        raise OSError("powershell missing")

    monkeypatch.setattr(_sp, "run", _boom)
    diag = diagnose_dns_visibility()
    assert diag["error"] is not None
    assert "could not be diagnosed" in diag["conclusion"]


@pytest.mark.skipif(sys.platform == "win32", reason="asserts the non-Windows gate")
def test_dns_endpoints_never_spawn_powershell_off_windows(tmp_path, monkeypatch):
    """
    DNS-cache enrichment and its diagnosis read the Windows DNS client
    through PowerShell. Off Windows the endpoints still answer in their
    usual shape - the dashboard calls both - but say the source is
    Windows-only, and no process is spawned to find that out.
    """
    import subprocess as _sp

    from fastapi.testclient import TestClient

    from app.api.deps import get_db
    from app.main import app
    from app.services.enrichment import reset_enrichment_service

    spawned: list = []

    def _refuse(*a, **k):
        spawned.append(a[0] if a else k.get("args"))
        raise AssertionError(f"unexpected subprocess: {spawned[-1]}")

    monkeypatch.setattr(_sp, "run", _refuse)
    monkeypatch.setattr(_sp, "Popen", _refuse)

    db = Database(db_path=str(tmp_path / "dns_gate.db"))
    db.initialize()
    reset_enrichment_service(None)
    app.dependency_overrides[get_db] = lambda: db
    try:
        client = TestClient(app)
        refreshed = client.post("/api/v1/enrichment/dns/refresh")
        assert refreshed.status_code == 200
        body = refreshed.json()
        assert body["succeeded"] is False
        assert "windows" in body["error"].lower()

        diagnosed = client.get("/api/v1/enrichment/dns/diagnose")
        assert diagnosed.status_code == 200
        diag = diagnosed.json()
        assert "windows" in (diag["error"] or "").lower()
        assert "windows" in diag["conclusion"].lower()
    finally:
        app.dependency_overrides.clear()
        reset_enrichment_service(None)
        db.close()
    assert spawned == []


# ──────────────────────────────────────────────────────────────────
# The DNS-Client event channel (ADR-119)
# ──────────────────────────────────────────────────────────────────


def _diagnose_with(monkeypatch, payload: dict):
    import json as _json
    import subprocess as _sp

    class _Proc:
        returncode = 0
        stdout = _json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(_sp, "run", lambda *a, **k: _Proc())
    return diagnose_dns_visibility()


def test_a_disabled_event_channel_is_named_as_a_cause(monkeypatch):
    """
    The state measured on a real Windows 11 Home machine, 22 Oct 2026.

    Provider present, Operational channel DISABLED — the Windows default
    — and the cache empty. Reporting the empty cache alone invites the
    reader to think the cache is the only place host DNS evidence could
    come from, and that PraHari is failing to read it. Both halves have
    to be stated for the conclusion to be honest.
    """
    diag = _diagnose_with(
        monkeypatch,
        {
            "doh_servers": [],
            "interfaces": [{"interface": "Wi-Fi", "servers": ["1.1.1.1", "8.8.8.8"]}],
            "cache_entries": 0,
            "dnscache_service": "Running",
            "event_channel_present": True,
            "event_channel_enabled": False,
            "event_channel_records": None,
        },
    )

    assert diag["event_channel_present"] is True
    assert diag["event_channel_enabled"] is False

    channel_causes = [c for c in diag["likely_causes"] if "Operational" in c]
    assert channel_causes, "a disabled DNS event channel was not reported"
    cause = channel_causes[0]
    assert "DISABLED" in cause
    assert "Administrator" in cause, "the cost of enabling it must be stated"
    # It must NOT promise that enabling the channel yields query names.
    # Discovery could not inspect a single field, because the channel
    # was off, so that remains unestablished.
    assert "has NOT been established" in cause


def test_an_absent_provider_is_distinguished_from_a_disabled_channel(monkeypatch):
    diag = _diagnose_with(
        monkeypatch,
        {
            "doh_servers": [],
            "interfaces": [],
            "cache_entries": 0,
            "dnscache_service": "Running",
            "event_channel_present": False,
            "event_channel_enabled": False,
            "event_channel_records": None,
        },
    )
    causes = " ".join(diag["likely_causes"])
    assert "not present on" in causes
    assert "DISABLED" not in causes, "an absent provider was reported as disabled"


def test_a_probe_that_does_not_report_the_channel_says_unknown(monkeypatch):
    """
    An older agent omits these keys. Unknown must not collapse to
    "absent": claiming there is no event channel when nobody looked is
    exactly the fabrication this project refuses.
    """
    diag = _diagnose_with(
        monkeypatch,
        {
            "doh_servers": [],
            "interfaces": [],
            "cache_entries": 0,
            "dnscache_service": "Running",
        },
    )
    assert diag["event_channel_present"] is None
    assert diag["event_channel_enabled"] is None
    causes = " ".join(diag["likely_causes"])
    assert "Operational" not in causes
    assert "not present on" not in causes

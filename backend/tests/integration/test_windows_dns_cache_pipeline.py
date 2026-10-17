"""
PraHari — The Windows DNS-Cache Pipeline, Through Real PowerShell.

On the validation host the Windows DNS client cache was empty: an
unfiltered `@(Get-DnsClientCache).Count` returned 0. A refresh therefore
"succeeded" with nothing to parse, and live DNS parsing went unproven.
Populating the cache would mean sending DNS queries or editing the hosts
file, which are network and system changes, so neither was done.

These tests prove everything up to the cmdlet itself, on real Windows:

* the property names the script reads exist on the real
  `MSFT_DNSClientCache` CIM class, read from the operating system. A wrong
  name would make the filter match nothing and a full cache look empty,
  which is indistinguishable from the symptom observed;
* the script's own PowerShell - filtering, projection, single-item
  handling and `ConvertTo-Json` - runs in real PowerShell over genuine
  instances of that class, created client-only with `New-CimInstance
  -ClientOnly` (in memory, never written to the system);
* Python parses that output and records observations into a temporary
  database.

Only `Get-DnsClientCache` is replaced: a PowerShell function of the same
name is defined ahead of the unmodified script, and PowerShell resolves
functions before cmdlets. Whether the real cmdlet returns populated
objects on a host with a non-empty cache remains the one unproven step.
"""

from __future__ import annotations

import re
import subprocess
import sys

import pytest

from app.services import enrichment
from app.services.enrichment import DomainEnrichmentService, query_windows_dns_cache
from app.storage.database import Database

pytestmark = [
    pytest.mark.live_windows,
    pytest.mark.skipif(sys.platform != "win32", reason="real PowerShell and the DnsClient CIM class"),
]

ORIGINAL_SCRIPT = enrichment._PS_DNS_CACHE_SCRIPT


def _ps_record(entry, name, rtype, data, ttl=300):
    return (
        "New-CimInstance -CimClass $class -ClientOnly -Property @{ "
        f"Entry='{entry}'; Name='{name}'; Type=[uint16]{rtype}; Data='{data}'; "
        f"TimeToLive=[uint32]{ttl}; Status=[uint32]0; Section=[byte]1; DataLength=[uint16]4 }}"
    )


def _fake_cache(*records: str) -> str:
    """A Get-DnsClientCache that returns client-only instances of the real class."""
    body = "\n".join(f"    {r}" for r in records) or "    # an empty cache"
    return (
        "function Get-DnsClientCache {\n"
        "    [CmdletBinding()] param()\n"
        "    $class = Get-CimClass -Namespace root/StandardCimv2 -ClassName MSFT_DNSClientCache\n"
        f"{body}\n"
        "}\n"
    )


@pytest.fixture
def with_cache(monkeypatch):
    def install(*records: str) -> None:
        monkeypatch.setattr(enrichment, "_PS_DNS_CACHE_SCRIPT", _fake_cache(*records) + ORIGINAL_SCRIPT)
    return install


@pytest.fixture
def db(tmp_path):
    database = Database(db_path=str(tmp_path / "dns.db"))
    database.initialize()
    yield database
    database.close()


def test_the_script_reads_only_properties_the_real_class_has():
    used = set(re.findall(r"\$_\.(\w+)", ORIGINAL_SCRIPT))
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "(Get-CimClass -Namespace root/StandardCimv2 -ClassName MSFT_DNSClientCache)"
         ".CimClassProperties.Name -join ','"],
        capture_output=True, text=True, timeout=60,
    )
    real = set(out.stdout.strip().split(","))

    assert {"Entry", "Name", "Type", "Data", "TimeToLive"} <= used
    assert used <= real, f"the script reads properties the OS class lacks: {sorted(used - real)}"


def test_address_records_pass_and_everything_else_is_filtered_in_powershell(with_cache):
    with_cache(
        _ps_record("portal.example.test", "portal.example.test", 1, "203.0.113.7"),
        _ps_record("portal.example.test", "portal.example.test", 28, "2001:db8::7"),
        _ps_record("alias.example.test", "alias.example.test", 5, "portal.example.test"),  # CNAME
        _ps_record("empty.example.test", "empty.example.test", 1, ""),                    # no data
    )

    records = query_windows_dns_cache()

    assert [(r["hostname"], r["data"], r["type"]) for r in records] == [
        ("portal.example.test", "203.0.113.7", 1),
        ("portal.example.test", "2001:db8::7", 28),
    ]
    assert all(r["ttl"] == 300 for r in records)


def test_a_single_cached_record_still_arrives_as_a_list(with_cache):
    """ConvertTo-Json unwraps single items unless the script prevents it."""
    with_cache(_ps_record("one.example.test", "one.example.test", 1, "198.51.100.1"))

    records = query_windows_dns_cache()

    assert isinstance(records, list) and len(records) == 1
    assert records[0]["data"] == "198.51.100.1"


def test_an_empty_cache_is_an_empty_list(with_cache):
    with_cache()
    assert query_windows_dns_cache() == []


def test_the_whole_path_records_normalised_observations(with_cache, db):
    with_cache(
        _ps_record("API.Example.TEST.", "API.Example.TEST.", 1, "203.0.113.20", ttl=120),
        _ps_record("cdn.example.test", "cdn.example.test", 28, "2001:0db8:0000:0000:0000:0000:0000:0020"),
        _ps_record("shared-a.example.test", "shared-a.example.test", 1, "198.51.100.9"),
        _ps_record("shared-b.example.test", "shared-b.example.test", 1, "198.51.100.9"),
        _ps_record("alias.example.test", "alias.example.test", 5, "cdn.example.test"),
    )
    service = DomainEnrichmentService(db=db)  # the real query function

    result = service.refresh_from_dns_cache()

    assert result["succeeded"] is True
    assert result["entries_read"] == 4, "the CNAME never leaves PowerShell"
    assert result["observations_recorded"] == 4
    assert db.get_dns_observations_for_ip("203.0.113.20")[0]["hostname"] == "api.example.test"
    assert db.get_dns_observations_for_ip("203.0.113.20")[0]["ttl_seconds"] == 120
    assert db.get_dns_observations_for_ip("2001:db8::20")[0]["hostname"] == "cdn.example.test", (
        "an IPv6 address is stored in its canonical compressed form"
    )
    shared = {o["hostname"] for o in db.get_dns_observations_for_ip("198.51.100.9")}
    assert shared == {"shared-a.example.test", "shared-b.example.test"}, (
        "a shared address keeps every name seen for it"
    )

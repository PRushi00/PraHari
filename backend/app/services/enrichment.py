"""
PraHari — Domain Enrichment Service

Associates a destination IP address with a hostname using **locally observed
DNS resolutions** read from the Windows DNS client cache
(``Get-DnsClientCache``). No query is sent anywhere: the cache already holds
answers this machine received, so reading it adds no network traffic, needs
no elevation, and changes no configuration.

Why this is an inference, not a fact
------------------------------------
A TCP connection records an address, not a name. Associating a name with it
is always reconstruction after the fact, and several ordinary conditions make
it unreliable:

  * **Shared addresses and CDNs.** One address commonly serves hundreds of
    hostnames, so an address alone cannot identify which was requested.
  * **Changing answers.** DNS responses rotate; the name cached now may not
    be the one the application resolved when it connected.
  * **Stale cache entries.** An entry can outlive the connection it relates
    to, or relate to no connection at all.
  * **Missing observations.** Encrypted DNS (DoH/DoT), a different resolver,
    a hosts-file entry, or a connection made by address never appear in the
    cache at all.
  * **Temporal ambiguity.** The cache records what is held now, not when each
    name was resolved relative to each connection.

Every attribution therefore travels with its method, its evidence timestamp,
the competing candidates, and an explicit confidence. Reverse DNS is **not**
used: a PTR record names the address's owner, not the hostname the
application asked for, and presenting it as the requested domain would be
straightforwardly misleading.

The connection record and its destination IP are never modified. Enrichment
is computed alongside and can always be ignored.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from app.schemas.events import (
    AttributionConfidence,
    DomainAttribution,
    DomainAttributionMethod,
    NormalizedEvent,
)
from app.storage.database import Database

logger = logging.getLogger(__name__)

# Evidence older than this is treated as too stale to support a confident
# association, because DNS answers rotate well within this period.
STALE_AFTER_SECONDS = 30 * 60

# More candidate hostnames than this for one address indicates a shared or
# CDN endpoint, where naming a single host would overstate what is known.
SHARED_IP_CANDIDATE_THRESHOLD = 2

# Record types that map a name to an address. CNAME entries point at another
# name, not an address, so they cannot anchor an IP attribution.
_ADDRESS_RECORD_TYPES = {1, 28}  # A, AAAA

CACHE_EMPTY_DIAGNOSIS = (
    "The Windows DNS client cache returned no address records, so hostnames "
    "cannot be inferred for connections. Several explanations are consistent "
    "with this — an application resolving names over its own encrypted DNS, "
    "the cache being unreadable without elevation, entries having expired, or "
    "connections made directly by IP — and host configuration alone does not "
    "establish which applies. See /api/v1/enrichment/dns/diagnose for the "
    "measured evidence. Reverse DNS can name the address owner instead, but "
    "never the hostname the application requested."
)


def _is_private(ip: str) -> bool:
    """True for loopback, link-local, private and otherwise non-routable addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )

_PS_DNS_CACHE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$rows = Get-DnsClientCache -ErrorAction SilentlyContinue |
    Where-Object { $_.Data -and $_.Entry -and ($_.Type -eq 1 -or $_.Type -eq 28) } |
    ForEach-Object {
        [pscustomobject]@{
            hostname = [string]$_.Entry
            name     = [string]$_.Name
            data     = [string]$_.Data
            type     = [int]$_.Type
            ttl      = [int]$_.TimeToLive
        }
    }
if ($null -eq $rows) { '[]' } else { ConvertTo-Json -InputObject @($rows) -Compress -Depth 3 }
"""


class DnsCacheUnavailable(RuntimeError):
    """Raised when the Windows DNS client cache cannot be read."""


def windows_only_dns_message() -> str:
    return (
        "DNS cache enrichment reads the Windows DNS client cache and is "
        f"unavailable on platform '{sys.platform}'. Hostnames are not "
        "attributed from local DNS evidence on this host."
    )


def query_windows_dns_cache(
    timeout_seconds: float = 20.0,
    powershell_path: str = "powershell",
) -> list[dict[str, Any]]:
    """
    Read A/AAAA entries from the local Windows DNS client cache.

    Returns raw ``{hostname, data, type, ttl}`` records. Reading the cache
    sends no DNS queries and requires no privileges.

    Windows only. Elsewhere it refuses before spawning anything: there is
    no Windows DNS client to read, and a `powershell` on PATH (PowerShell
    Core exists for Linux) would not have the DnsClient module either.
    """
    if sys.platform != "win32":
        raise DnsCacheUnavailable(windows_only_dns_message())
    try:
        proc = subprocess.run(
            [powershell_path, "-NoProfile", "-NonInteractive", "-Command", _PS_DNS_CACHE_SCRIPT],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError as exc:
        raise DnsCacheUnavailable(
            f"PowerShell executable '{powershell_path}' not found; DNS cache "
            "enrichment is unavailable on this host."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise DnsCacheUnavailable(
            f"DNS cache query timed out after {timeout_seconds}s"
        ) from exc

    if proc.returncode != 0:
        raise DnsCacheUnavailable(
            f"DNS cache query failed (exit {proc.returncode}): "
            f"{(proc.stderr or '').strip()[:300]}"
        )

    raw = (proc.stdout or "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DnsCacheUnavailable(
            f"DNS cache query returned unparseable output: {raw[:200]!r}"
        ) from exc

    if isinstance(parsed, dict):
        return [parsed]
    return [r for r in parsed if isinstance(r, dict)]


class DomainEnrichmentService:
    """Records DNS observations and attributes hostnames to destination IPs."""

    def __init__(self, db: Database, query_fn=None):
        self.db = db
        self._query_fn = query_fn or query_windows_dns_cache
        self.last_refresh_at: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.refresh_count = 0
        self.observations_recorded = 0
        self.cache_appears_unavailable = False
        self._reverse_cache: dict[str, DomainAttribution] = {}

    # ──────────────── collection ────────────────

    def refresh_from_dns_cache(self) -> dict[str, Any]:
        """
        Snapshot the local DNS cache into the observation store.

        Observations accumulate: a new answer never overwrites an old one, so
        a shared address keeps showing every name seen for it.
        """
        now = datetime.now(timezone.utc)
        try:
            records = self._query_fn()
        except DnsCacheUnavailable as exc:
            self.last_error = str(exc)
            logger.warning("DNS cache refresh failed: %s", exc)
            return {
                "succeeded": False,
                "error": str(exc),
                "entries_read": 0,
                "observations_recorded": 0,
            }

        observations: list[dict[str, Any]] = []
        skipped = 0
        for rec in records:
            hostname = str(rec.get("hostname") or "").strip().rstrip(".")
            data = str(rec.get("data") or "").strip()
            if not hostname or not data:
                skipped += 1
                continue
            try:
                rtype = int(rec.get("type") or 0)
            except (TypeError, ValueError):
                rtype = 0
            if rtype not in _ADDRESS_RECORD_TYPES:
                skipped += 1
                continue
            try:
                ip = str(ipaddress.ip_address(data))
            except ValueError:
                # CNAME chains and malformed entries land here.
                skipped += 1
                continue

            ttl = rec.get("ttl")
            observations.append(
                {
                    "ip_address": ip,
                    "hostname": hostname.lower(),
                    "observed_at": now.isoformat(),
                    "method": DomainAttributionMethod.DNS_CACHE_OBSERVATION.value,
                    "ttl_seconds": int(ttl) if isinstance(ttl, (int, float)) else None,
                    "source_id": "windows_dns_cache",
                }
            )

        recorded = self.db.record_dns_observations(observations)
        self.last_refresh_at = now
        self.last_error = None
        self.refresh_count += 1
        self.observations_recorded += recorded
        # An empty cache is reported as such rather than passed off as "no
        # new domains". On this class of host it usually means the resolver
        # cache is not readable or not populated, which is a visibility
        # limitation the operator needs to know about.
        self.cache_appears_unavailable = len(records) == 0

        logger.info(
            "DNS cache refresh: %d entries read, %d address records, %d new observations",
            len(records), len(observations), recorded,
        )
        return {
            "succeeded": True,
            "error": None,
            "entries_read": len(records),
            "address_records": len(observations),
            "skipped_non_address_records": skipped,
            "observations_recorded": recorded,
            "refreshed_at": now.isoformat(),
            "cache_appears_unavailable": self.cache_appears_unavailable,
            "diagnosis": (
                CACHE_EMPTY_DIAGNOSIS if self.cache_appears_unavailable else None
            ),
        }

    # ──────────────── attribution ────────────────

    def attribute_ip(
        self,
        ip: Optional[str],
        observations: Optional[list[dict]] = None,
        reference_time: Optional[datetime] = None,
    ) -> DomainAttribution:
        """
        Best defensible hostname for an address, with its evidence.

        Returns an unattributed result rather than guessing when the evidence
        does not support a conclusion.
        """
        if not ip:
            return DomainAttribution(
                limitations=["No destination IP on this record."]
            )

        if observations is None:
            observations = self.db.get_dns_observations_for_ip(ip)

        if not observations:
            return DomainAttribution(
                method=DomainAttributionMethod.NONE,
                confidence=AttributionConfidence.NONE,
                limitations=[
                    "No local DNS observation exists for this address. The "
                    "connection may have been made by IP, resolved via "
                    "encrypted DNS (DoH/DoT) or another resolver, resolved "
                    "before collection began, or already expired from the cache."
                ],
            )

        now = reference_time or datetime.now(timezone.utc)

        # Newest observation per hostname, keeping the method that produced
        # it so the attribution reports how it was actually obtained.
        newest: dict[str, datetime] = {}
        methods: dict[str, str] = {}
        for obs in observations:
            host = obs["hostname"]
            ts = self._parse_ts(obs.get("observed_at"))
            if ts is None:
                continue
            if host not in newest or ts > newest[host]:
                newest[host] = ts
                methods[host] = obs.get("method") or (
                    DomainAttributionMethod.DNS_CACHE_OBSERVATION.value
                )

        if not newest:
            return DomainAttribution(
                limitations=["DNS observations for this address have unparseable timestamps."]
            )

        ranked = sorted(newest.items(), key=lambda kv: kv[1], reverse=True)
        best_host, best_ts = ranked[0]
        candidates = [h for h, _ in ranked]
        age = (now - best_ts).total_seconds()

        limitations: list[str] = [
            "Hostname is inferred from a local DNS observation, not recorded by "
            "the connection itself. It indicates a name that resolved to this "
            "address, which is not proof that the application requested it.",
        ]

        # Start optimistic, then demote for each weakening condition.
        confidence = AttributionConfidence.HIGH

        if len(candidates) >= SHARED_IP_CANDIDATE_THRESHOLD:
            confidence = AttributionConfidence.MEDIUM
            limitations.append(
                f"{len(candidates)} different hostnames have resolved to this "
                "address, which is typical of shared hosting and CDNs. The "
                "specific hostname used by this connection cannot be determined "
                "from the address alone."
            )

        if age > STALE_AFTER_SECONDS:
            confidence = AttributionConfidence.LOW
            limitations.append(
                f"The supporting DNS observation is {int(age // 60)} minutes old; "
                "DNS answers rotate, so it may not correspond to this connection."
            )
        elif confidence is AttributionConfidence.HIGH:
            limitations.append(
                "Supported by a single recent local resolution for this exact address."
            )

        try:
            best_method = DomainAttributionMethod(methods.get(best_host, ""))
        except ValueError:
            best_method = DomainAttributionMethod.DNS_CACHE_OBSERVATION

        return DomainAttribution(
            hostname=best_host,
            method=best_method,
            confidence=confidence,
            identifies_requested_host=True,
            attribution_kind="requested_host",
            evidence_observed_at=best_ts,
            evidence_age_seconds=round(age, 1),
            candidate_hostnames=candidates[:10],
            candidate_count=len(candidates),
            limitations=limitations,
        )

    def reverse_lookup(self, ip: str, timeout_seconds: float = 2.0) -> DomainAttribution:
        """
        Resolve an address to its PTR record (opt-in).

        This answers "who owns this address", not "what did the application
        request". A CDN edge returns something like
        ``server-x-y-z.ams50.r.cloudfront.net`` no matter which of the
        thousands of sites behind it was actually visited. The result is
        therefore always LOW confidence and is explicitly marked as NOT
        identifying the requested host, so it cannot be read as the domain
        the user browsed to.

        A PTR lookup is ordinary name resolution through the system
        resolver. It sends no telemetry anywhere and discloses only
        addresses this machine has already contacted — but because it does
        generate network traffic, it is disabled by default.
        """
        try:
            socket.setdefaulttimeout(timeout_seconds)
            hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
        except (OSError, socket.herror, socket.gaierror):
            return DomainAttribution(
                method=DomainAttributionMethod.REVERSE_DNS,
                confidence=AttributionConfidence.NONE,
                attribution_kind="none",
                identifies_requested_host=False,
                limitations=[
                    f"No PTR record is published for {ip}; the address owner "
                    "cannot be named, and the requested hostname remains unknown."
                ],
            )
        finally:
            socket.setdefaulttimeout(None)

        return DomainAttribution(
            hostname=hostname.rstrip(".").lower(),
            method=DomainAttributionMethod.REVERSE_DNS,
            confidence=AttributionConfidence.LOW,
            evidence_observed_at=datetime.now(timezone.utc),
            evidence_age_seconds=0.0,
            identifies_requested_host=False,
            attribution_kind="infrastructure_owner",
            limitations=[
                "REVERSE DNS: this names the owner of the IP address, NOT the "
                "hostname the application requested.",
                "For shared hosting and CDNs the PTR record identifies the edge "
                "server, which is unrelated to the site actually visited.",
                "Do not present this value as the browsed domain.",
            ],
        )

    def attribute_events(
        self,
        events: Iterable[NormalizedEvent],
        allow_reverse_dns: bool = False,
    ) -> dict[str, DomainAttribution]:
        """
        Attribute a batch of events in one pass, keyed by ``event_id``.

        Precedence, strongest evidence first:
          1. a hostname reported by the source itself (app-layer),
          2. a local DNS resolution this machine performed,
          3. optionally, reverse DNS — which names the address owner only and
             is never treated as the requested host.
        """
        events = list(events)
        if not events:
            return {}

        ips = [e.dst_ip for e in events if e.dst_ip]
        bulk = self.db.get_dns_observations_for_ips(ips)
        now = datetime.now(timezone.utc)

        out: dict[str, DomainAttribution] = {}
        for ev in events:
            if ev.dst_hostname:
                out[ev.event_id] = DomainAttribution(
                    hostname=ev.dst_hostname,
                    method=DomainAttributionMethod.APPLICATION_LAYER_REPORTED,
                    confidence=AttributionConfidence.HIGH,
                    identifies_requested_host=True,
                    attribution_kind="requested_host",
                    evidence_observed_at=ev.observed_at,
                    evidence_age_seconds=0.0,
                    limitations=[
                        "Hostname was reported directly by the telemetry source "
                        "that observed the request, not inferred from DNS."
                    ],
                )
                continue
            attribution = self.attribute_ip(
                ev.dst_ip, observations=bulk.get(ev.dst_ip or "", []), reference_time=now
            )
            if (
                allow_reverse_dns
                and not attribution.is_attributed
                and ev.dst_ip
                and not _is_private(ev.dst_ip)
            ):
                # Only as a last resort, and only for routable addresses:
                # private ranges have no meaningful public PTR.
                attribution = self._cached_reverse_lookup(ev.dst_ip)
            out[ev.event_id] = attribution
        return out

    def _cached_reverse_lookup(self, ip: str) -> DomainAttribution:
        """Reverse lookup with a process-local cache, to avoid repeat queries."""
        cached = self._reverse_cache.get(ip)
        if cached is not None:
            return cached
        result = self.reverse_lookup(ip)
        self._reverse_cache[ip] = result
        return result

    def hostname_for_event(self, event: NormalizedEvent) -> Optional[str]:
        """
        Convenience resolver for aggregation.

        Returns a hostname only at MEDIUM confidence or better, so weak
        evidence does not silently shape analytics totals.
        """
        if event.dst_hostname:
            return event.dst_hostname
        attribution = self.attribute_ip(event.dst_ip)
        # Only names that speak to the host actually requested are aggregated.
        # Folding infrastructure/PTR names into "top domains" would imply the
        # user visited a CDN edge server.
        if attribution.identifies_requested_host and attribution.confidence in (
            AttributionConfidence.HIGH,
            AttributionConfidence.MEDIUM,
        ):
            return attribution.hostname
        return None

    # ──────────────── status ────────────────

    def status(self) -> dict[str, Any]:
        return {
            "method": DomainAttributionMethod.DNS_CACHE_OBSERVATION.value,
            "last_refresh_at": self.last_refresh_at.isoformat() if self.last_refresh_at else None,
            "refresh_count": self.refresh_count,
            "observations_recorded": self.observations_recorded,
            "total_observations_stored": self.db.count_dns_observations(),
            "distinct_ips_with_evidence": self.db.count_dns_distinct_ips(),
            "stale_after_seconds": STALE_AFTER_SECONDS,
            "cache_appears_unavailable": self.cache_appears_unavailable,
            "diagnosis": CACHE_EMPTY_DIAGNOSIS if self.cache_appears_unavailable else None,
            "last_error": self.last_error,
            "limitations": [
                "Hostnames are inferred from locally cached DNS answers, never recorded by the connection itself.",
                "Reverse DNS is deliberately not used: a PTR record names the address owner, not the hostname an application requested.",
                "Shared and CDN addresses serve many hostnames; such attributions are capped at MEDIUM confidence.",
                "Connections made by IP, or resolved via encrypted DNS (DoH/DoT) or another resolver, produce no observation and remain unattributed.",
                "No DNS query is sent and no external enrichment service is contacted.",
            ],
        }

    @staticmethod
    def _parse_ts(value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ──────────────── singleton accessor ────────────────

_service: Optional[DomainEnrichmentService] = None


def get_enrichment_service(db: Database) -> DomainEnrichmentService:
    global _service
    if _service is None or _service.db is not db:
        _service = DomainEnrichmentService(db=db)
    return _service


def reset_enrichment_service(db: Optional[Database] = None, **kwargs) -> Optional[DomainEnrichmentService]:
    global _service
    _service = DomainEnrichmentService(db=db, **kwargs) if db is not None else None
    return _service


# ──────────────────────────────────────────────────────────────────
# DNS visibility diagnosis
# ──────────────────────────────────────────────────────────────────

_PS_DNS_DIAGNOSE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$doh = @()
try {
    $doh = Get-DnsClientDohServerAddress |
        ForEach-Object {
            [pscustomobject]@{
                server       = [string]$_.ServerAddress
                template     = [string]$_.DohTemplate
                auto_upgrade = [bool]$_.AutoUpgrade
            }
        }
} catch {}

$ifaces = @()
try {
    $ifaces = Get-DnsClientServerAddress -AddressFamily IPv4 |
        Where-Object { $_.ServerAddresses } |
        ForEach-Object {
            [pscustomobject]@{
                interface = [string]$_.InterfaceAlias
                servers   = @($_.ServerAddresses)
            }
        }
} catch {}

$cacheCount = 0
try { $cacheCount = @(Get-DnsClientCache).Count } catch {}

$svc = 'unknown'
try { $svc = [string](Get-Service -Name Dnscache).Status } catch {}

ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{
    doh_servers      = @($doh)
    interfaces       = @($ifaces)
    cache_entries    = $cacheCount
    dnscache_service = $svc
})
"""


def diagnose_dns_visibility(
    timeout_seconds: float = 20.0,
    powershell_path: str = "powershell",
) -> dict[str, Any]:
    """
    Explain WHY local DNS evidence is or is not available on this host.

    Read-only: it inspects resolver configuration and cache occupancy. It
    changes no setting, flushes nothing, and sends no query.

    The distinction that matters is between "this host resolves names in a
    way PraHari cannot observe" and "PraHari is failing to read something
    that is there". Reporting an empty cache without that context invites
    the reader to assume the latter.
    """
    result: dict[str, Any] = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cache_entries": 0,
        "doh_auto_upgrade_enabled": False,
        "doh_servers_known": [],
        "doh_auto_upgrade_servers": [],
        "active_resolvers": [],
        "resolvers_in_known_doh_table": [],
        "resolvers_with_doh_auto_upgrade": [],
        "dnscache_service": "unknown",
        "likely_causes": [],
        "conclusion": "",
        "error": None,
    }

    try:
        proc = subprocess.run(
            [powershell_path, "-NoProfile", "-NonInteractive", "-Command", _PS_DNS_DIAGNOSE],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = (proc.stdout or "").strip()
        data = json.loads(raw) if raw else {}
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["conclusion"] = (
            "DNS visibility could not be diagnosed on this host; hostname "
            "attribution remains unavailable."
        )
        return result

    doh_entries = data.get("doh_servers") or []
    doh_servers = {str(d.get("server")) for d in doh_entries if d.get("server")}
    # Windows ships a built-in table of WELL-KNOWN DoH servers. An entry
    # here means "this address is known to offer DoH", NOT that this machine
    # uses DoH. Only AutoUpgrade indicates the resolver would actually
    # upgrade to encrypted DNS.
    doh_auto = {
        str(d.get("server"))
        for d in doh_entries
        if d.get("server") and d.get("auto_upgrade")
    }
    result["doh_servers_known"] = sorted(doh_servers)
    result["doh_auto_upgrade_servers"] = sorted(doh_auto)
    result["doh_auto_upgrade_enabled"] = bool(doh_auto)
    result["cache_entries"] = int(data.get("cache_entries") or 0)
    result["dnscache_service"] = str(data.get("dnscache_service") or "unknown")

    active: list[str] = []
    for iface in data.get("interfaces") or []:
        for srv in iface.get("servers") or []:
            active.append(str(srv))
    result["active_resolvers"] = sorted(set(active))
    result["resolvers_in_known_doh_table"] = sorted(set(active) & doh_servers)
    result["resolvers_with_doh_auto_upgrade"] = sorted(set(active) & doh_auto)

    causes: list[str] = []
    if result["cache_entries"] == 0:
        # Candidate explanations, none of which the available read-only
        # evidence can confirm on its own. They are listed as possibilities,
        # not asserted as the cause.
        if result["resolvers_with_doh_auto_upgrade"]:
            causes.append(
                "The configured resolvers ("
                + ", ".join(result["resolvers_with_doh_auto_upgrade"])
                + ") are set to auto-upgrade to DNS-over-HTTPS. DoH resolution "
                "does not populate the Windows resolver cache, which would "
                "explain the absence of local answers."
            )
        elif result["resolvers_in_known_doh_table"]:
            causes.append(
                "The configured resolvers ("
                + ", ".join(result["resolvers_in_known_doh_table"])
                + ") appear in Windows' built-in table of well-known DoH "
                "servers, but auto-upgrade is OFF for them. That table records "
                "which servers OFFER DoH; it is NOT evidence that this machine "
                "used DoH for any particular connection."
            )
        causes.append(
            "An application may perform its own encrypted DNS (browsers "
            "commonly do), bypassing the Windows resolver regardless of system "
            "settings. This cannot be confirmed from host configuration alone."
        )
        causes.append(
            "Reading the cache via ipconfig /displaydns requires elevation on "
            "this host, and Get-DnsClientCache returns an empty set without "
            "raising an error. A populated-but-unreadable cache therefore "
            "cannot be excluded without elevation, which PraHari does not perform."
        )
        causes.append(
            "Applications that connect by IP address perform no DNS lookup at all."
        )
        causes.append(
            "Cached entries may simply have expired before collection ran."
        )
        result["conclusion"] = (
            "No local DNS evidence is obtainable on this host, so destination "
            "hostnames cannot be attributed and are correctly reported as "
            "unknown. The specific cause is NOT established by the read-only "
            "evidence available: several explanations remain consistent with "
            "what was measured. This is a visibility limit, not a collection "
            "failure."
        )
    else:
        result["conclusion"] = (
            f"{result['cache_entries']} cached DNS record(s) are visible and "
            "available as attribution evidence."
        )

    result["likely_causes"] = causes
    return result

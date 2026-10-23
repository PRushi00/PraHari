"""
PraHari — Windows DNS-Client event log adapter (ADR-120).

Reads `Microsoft-Windows-DNS-Client/Operational` and turns event **3008**
records into DNS observations: evidence that, at a moment, a name
resolved to one or more addresses.

What the evidence actually is
-----------------------------
Discovery on a real Windows 11 Home machine (ADR-119, then enabled by the
operator) found the channel readable **without elevation**, holding 216
records across three event ids. One 3008 record was captured in full:

    TimeCreated   2026-10-22T12:09:56.4674908Z
    ProcessId     13268
    QueryName     localhost
    QueryType     1
    QueryOptions  720575941721587776
    QueryStatus   0
    QueryResults  127.0.0.1;

That is the entire basis for this parser. Everything it does is derived
from that record and from the Windows error-code convention that
`QueryStatus == 0` means success.

What this deliberately does NOT do
----------------------------------
* **Only 3008 is interpreted.** The channel carries **17 distinct event
  ids**, not the three the first sample suggested (ADR-121). Every other
  id is counted and reported by number, never parsed.
* **No lookup is attributed to an application.** 3006 and 3008 are the
  only two ids carrying no `ClientPID`. The `ProcessId` on the record
  identifies the process that EMITTED it, which is not established to be
  the one that resolved the name — so it is stored as
  `logging_process_id` and never presented as the requester. Ids
  3010/3011/3020 do carry `ClientPID`; interpreting them is future work
  with its own evidence.
* **`QueryOptions` is carried raw.** It is a bitfield this project has
  never decoded. A partial decode would invite readers to trust flags
  nobody verified.
* **A failed query records no observation.** `QueryStatus != 0` means the
  resolution did not succeed, so there is no name-to-address fact to
  store — only that it was attempted.
* **An empty `QueryResults` records no observation.** A 3008 with a name
  and no addresses says a lookup happened, not what it resolved to.

Why observations and not events
-------------------------------
A DNS lookup is not a connection flow, and `dns_observations` already
exists for exactly this: append-only name/address evidence carrying the
method that produced it. `DomainAttributionMethod.DNS_QUERY_LOG` was
already defined before this adapter existed. Cache enrichment is
untouched — it writes the same table under a different `method`, and
attribution reports whichever produced the row.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from app.schemas.events import DomainAttributionMethod

logger = logging.getLogger(__name__)

CHANNEL = "Microsoft-Windows-DNS-Client/Operational"

#: The only event id whose fields this project has observed.
QUERY_COMPLETED_EVENT_ID = 3008

#: Ids observed in this channel whose records this adapter does not
#: parse. The measured set is 17 ids (ADR-121); these two are named
#: because their meaning IS now known and they are still not parsed:
#:
#:   3006  the request side of a lookup, pairing with 3008's completion.
#:         Nothing in either record links a pair, so no correlation is
#:         claimed and neither is treated as implying the other.
#:   1001  not a query at all — per-interface resolver configuration,
#:         carrying a hex SOCKADDR blob whose layout is unverified.
#:
#: Any other id is counted under its own number by the same path, so
#: this tuple being incomplete can never cause one to be parsed.
UNINTERPRETED_EVENT_IDS = (3006, 1001)

#: Windows reports success as 0; any other value is an error code whose
#: meaning this project has not established.
QUERY_STATUS_SUCCESS = 0


class DnsEventLogUnavailable(RuntimeError):
    """The DNS-Client event channel could not be read on this host."""


@dataclass
class DnsEventObservation:
    """One name-to-address fact, with the evidence it came from."""

    ip_address: str
    hostname: str
    observed_at: str
    query_type: Optional[int]
    #: The PID on the event RECORD — the process that emitted it. For
    #: 3008 this is NOT established to be the application that made the
    #: lookup: 3006 and 3008 are the only two ids in this channel that
    #: carry no `ClientPID` field, which is the one that would identify
    #: the requester (ADR-121). Named for what it is, so nothing reads
    #: it as attribution it has not earned.
    logging_process_id: Optional[int]
    query_options_raw: Optional[str]
    method: str = DomainAttributionMethod.DNS_QUERY_LOG.value

    def as_observation(self, source_id: Optional[str] = None) -> dict[str, Any]:
        """The shape `Database.record_dns_observations` stores."""
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "observed_at": self.observed_at,
            "method": self.method,
            # The channel does not report a TTL. Null, never guessed.
            "ttl_seconds": None,
            "source_id": source_id,
        }


@dataclass
class EventLogRead:
    """
    One read of the channel, with what a caller needs to move a bookmark
    safely (ADR-127).

    `records` is the batch. `newest_record_id` is the highest RecordId
    the channel currently holds, read separately — it is how a cleared
    log is detected, because Windows restarts RecordId at 1 after a
    clear and a bookmark above it is therefore stale.
    """

    records: list[dict[str, Any]]
    newest_record_id: int = 0
    requested_after: int = 0
    batch_limit: int = 0
    #: Which query produced this batch: "xpath" (the event-log service
    #: filtered), "fallback_window" (the proven newest-N read, filtered
    #: here instead) or "cold_start".
    filter_mode: str = "cold_start"
    #: Why the filtered query was abandoned, when it was. Reported
    #: rather than swallowed: a filter that silently matches nothing
    #: looks exactly like a quiet network (ADR-128).
    filter_error: str = ""

    def new_records(self) -> list[dict[str, Any]]:
        """
        Records strictly newer than the bookmark.

        Applied on every path, not only the fallback. Correctness must
        not depend on the event-log filter having worked — if the XPath
        is wrong the window read still yields exactly the new records,
        and if it is right this drops nothing (ADR-128).
        """
        if self.requested_after <= 0:
            return list(self.records)
        return [
            r
            for r in self.records
            if (_as_int(r.get("RecordId")) or 0) > self.requested_after
        ]

    @property
    def possible_gap(self) -> bool:
        """
        The window read may not reach back to the bookmark.

        Only the fallback can lose events, and only when it filled its
        batch and its oldest record is already past the bookmark: the
        events in between scrolled out of the window between polls. Said
        out loud rather than left as a silent hole.
        """
        if self.filter_mode != "fallback_window" or not self.batch_was_full:
            return False
        ids = [_as_int(r.get("RecordId")) or 0 for r in self.records]
        return bool(ids) and min(ids) > self.requested_after + 1

    @property
    def max_record_id(self) -> int:
        """Highest RecordId in this batch, or 0 when it is empty."""
        ids = [_as_int(r.get("RecordId")) or 0 for r in self.records]
        return max(ids) if ids else 0

    @property
    def batch_was_full(self) -> bool:
        """
        The limit truncated the batch, so unread events remain.

        The caller should poll again promptly rather than sleep, or a
        burst would drain one interval at a time.
        """
        return self.batch_limit > 0 and len(self.records) >= self.batch_limit

    @property
    def log_was_reset(self) -> bool:
        """
        The bookmark sits above the newest record the channel holds.

        That happens when the log is cleared: RecordId restarts at 1.
        Continuing to filter on the stale bookmark would read nothing,
        for ever, while DNS activity carried on.
        """
        return (
            self.requested_after > 0
            and 0 < self.newest_record_id < self.requested_after
        )


@dataclass
class DnsEventParseReport:
    """
    What a batch of records yielded, and what it refused.

    Every input record is accounted for in exactly one bucket, so a
    reader can tell "nothing resolved" from "nothing was read".
    """

    observations: list[DnsEventObservation] = field(default_factory=list)
    records_read: int = 0
    #: 3008 records that yielded at least one address. Counted apart from
    #: `observations`, because one record can resolve to several addresses.
    successful_records: int = 0
    skipped_failed_query: int = 0
    skipped_no_results: int = 0
    skipped_malformed: int = 0
    uninterpreted_by_event_id: dict[int, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def uninterpreted_total(self) -> int:
        return sum(self.uninterpreted_by_event_id.values())

    def reconciles(self) -> bool:
        """
        Accounting identity: every record read landed somewhere.

        A 3008 record yields one bucket; the observations it produced may
        number more than one (a name can resolve to several addresses),
        so successful records are counted separately from the rows they
        made.
        """
        accounted = (
            self.successful_records
            + self.skipped_failed_query
            + self.skipped_no_results
            + self.skipped_malformed
            + self.uninterpreted_total
        )
        return accounted == self.records_read


def _parse_timestamp(raw: Any) -> Optional[str]:
    """
    Normalise an event timestamp to UTC ISO-8601.

    Windows reports 100-nanosecond precision (`...56.4674908Z`), which
    `fromisoformat` rejects before Python 3.11 and accepts after. The
    fractional part is truncated to microseconds rather than rounded:
    a timestamp is evidence, and inventing a sub-microsecond digit in
    either direction is not an improvement.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Truncate over-long fractional seconds: .4674908 -> .467490
    if "." in text:
        head, _, tail = text.partition(".")
        digits = ""
        rest = ""
        for index, char in enumerate(tail):
            if char.isdigit():
                digits += char
            else:
                rest = tail[index:]
                break
        if len(digits) > 6:
            digits = digits[:6]
        text = f"{head}.{digits}{rest}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # The channel reports UTC. A naive value is treated as UTC rather
        # than as local time, which would silently shift every record.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _parse_results(raw: Any) -> list[str]:
    """
    Split `QueryResults` into addresses.

    The one observed value was `127.0.0.1;` — semicolon separated with a
    trailing separator. Entries that are not addresses are dropped rather
    than stored: a CNAME target or a type-specific payload is not an
    `ip_address`, and putting one in that column would make the
    attribution table lie about what it holds.
    """
    if not isinstance(raw, str):
        return []
    out: list[str] = []
    for part in raw.split(";"):
        candidate = part.strip()
        if not candidate:
            continue
        if _looks_like_address(candidate):
            out.append(candidate)
    return out


def _looks_like_address(value: str) -> bool:
    """IPv4 or IPv6 by structure, without importing a resolver."""
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _as_int(raw: Any) -> Optional[int]:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.strip().lstrip("-").isdigit():
        return int(raw.strip())
    return None


def parse_dns_events(records: list[dict[str, Any]]) -> DnsEventParseReport:
    """
    Turn raw event records into observations, accounting for every one.

    Pure: no Windows, no subprocess, no clock. This is what the tests
    exercise, because the collection half cannot run anywhere but a
    Windows host with the channel enabled.
    """
    report = DnsEventParseReport(records_read=len(records))

    for record in records:
        if not isinstance(record, dict):
            report.skipped_malformed += 1
            continue

        event_id = _as_int(record.get("Id"))
        if event_id in UNINTERPRETED_EVENT_IDS:
            report.uninterpreted_by_event_id[event_id] = (
                report.uninterpreted_by_event_id.get(event_id, 0) + 1
            )
            continue
        if event_id != QUERY_COMPLETED_EVENT_ID:
            # An id this project has not seen at all. Counted as
            # uninterpreted under its own key, never parsed on the
            # assumption that it resembles 3008.
            if event_id is None:
                report.skipped_malformed += 1
            else:
                report.uninterpreted_by_event_id[event_id] = (
                    report.uninterpreted_by_event_id.get(event_id, 0) + 1
                )
            continue

        hostname = record.get("QueryName")
        observed_at = _parse_timestamp(record.get("TimeCreated"))
        if not isinstance(hostname, str) or not hostname.strip() or observed_at is None:
            report.skipped_malformed += 1
            continue

        status = _as_int(record.get("QueryStatus"))
        if status is None or status != QUERY_STATUS_SUCCESS:
            # The lookup did not succeed, so there is no name-to-address
            # fact. That a lookup was attempted is not recorded as a
            # resolution.
            report.skipped_failed_query += 1
            continue

        addresses = _parse_results(record.get("QueryResults"))
        if not addresses:
            report.skipped_no_results += 1
            continue

        report.successful_records += 1
        for address in addresses:
            report.observations.append(
                DnsEventObservation(
                    ip_address=address,
                    hostname=hostname.strip(),
                    observed_at=observed_at,
                    query_type=_as_int(record.get("QueryType")),
                    logging_process_id=_as_int(record.get("ProcessId")),
                    # Carried verbatim: an undecoded bitfield.
                    query_options_raw=(
                        str(record["QueryOptions"])
                        if record.get("QueryOptions") is not None
                        else None
                    ),
                )
            )

    if report.uninterpreted_total:
        seen = ", ".join(
            f"{event_id} x{count}"
            for event_id, count in sorted(report.uninterpreted_by_event_id.items())
        )
        report.notes.append(
            f"{report.uninterpreted_total} record(s) carried event ids this "
            f"adapter does not interpret ({seen}). They were counted, not "
            "parsed: no field of them has been observed, and naming them "
            "would be a guess that becomes an attributed hostname."
        )
    if report.skipped_failed_query:
        report.notes.append(
            f"{report.skipped_failed_query} query/queries did not succeed "
            "(QueryStatus != 0), so they record no name-to-address fact."
        )
    if report.skipped_no_results:
        report.notes.append(
            f"{report.skipped_no_results} successful query/queries carried no "
            "parseable address, so a lookup is known to have happened but not "
            "what it resolved to."
        )
    return report


# ──────────────────────────────────────────────────────────────────
# Collection (operating-system facing)
# ──────────────────────────────────────────────────────────────────

#: Read-only. It enables nothing, clears nothing, and sends no query.
#: `-MaxEvents` bounds the read so a full circular log cannot be pulled
#: into memory in one call.
#: Read the channel, optionally only what is newer than a bookmark.
#:
#: Two modes, because they need different guarantees (ADR-127):
#:
#: * **Cold start** (`after_record_id` = 0): the newest `max_events`,
#:   newest-first. The channel is circular and may already hold more
#:   history than anyone wants imported, so the first run seeds the
#:   bookmark instead of draining the backlog — and says so.
#: * **Incremental**: `EventRecordID > N` filtered **in the event-log
#:   query itself**, then sorted ascending and truncated to the OLDEST
#:   `max_events`. Sorting ascending is what makes the batch contiguous
#:   with the bookmark: taking the newest N of the matching set would
#:   leave an unread hole between the bookmark and the batch, and
#:   advancing past that hole would lose events silently.
#:
#: `newest_record_id` is reported separately so the caller can detect a
#: cleared or rolled log: Windows restarts RecordId at 1 after a clear,
#: so a newest id BELOW the bookmark means the bookmark is stale.
_PS_READ_EVENTS = r"""
$ErrorActionPreference = 'Stop'
try {{
    $log = Get-WinEvent -ListLog '{channel}' -ErrorAction Stop
}} catch {{
    Write-Output '{{"error":"channel_absent"}}'
    exit 0
}}
if (-not $log.IsEnabled) {{
    Write-Output '{{"error":"channel_disabled"}}'
    exit 0
}}
$after = {after_record_id}
$newestId = 0
$mode = 'cold_start'
$filterError = ''
try {{
    $newest = @(Get-WinEvent -LogName '{channel}' -MaxEvents 1 -ErrorAction Stop)
    if ($newest.Count -gt 0) {{ $newestId = [int64] $newest[0].RecordId }}
}} catch {{
    # An empty channel is not an error: it reports nothing yet.
    $newestId = 0
}}
$events = @()
if ($after -gt 0) {{
    # Preferred: let the event-log service do the filtering. This is the
    # cheap path, but it has never been proven on a real channel, so a
    # failure here must NOT silently read nothing — it falls back to the
    # window read that is known to work, and says which was used.
    try {{
        $filter = "*[System[EventRecordID>$after]]"
        $events = @(Get-WinEvent -LogName '{channel}' -FilterXPath $filter -ErrorAction Stop |
            Sort-Object -Property RecordId |
            Select-Object -First {max_events})
        $mode = 'xpath'
    }} catch {{
        $msg = $_.Exception.Message
        if ($msg -match 'No events were found') {{
            # Not a failure: the filter worked and nothing is newer.
            $events = @()
            $mode = 'xpath'
        }} else {{
            $filterError = ($msg -replace '"', "'")
            $mode = 'fallback_window'
        }}
    }}
}}
if ($mode -ne 'xpath') {{
    # The proven read: newest N, no filter. The caller drops anything at
    # or below its bookmark, so this stays incremental in effect.
    try {{
        $events = @(Get-WinEvent -LogName '{channel}' -MaxEvents {max_events} -ErrorAction Stop)
        if ($after -gt 0) {{ $events = @($events | Sort-Object -Property RecordId) }}
    }} catch {{
        Write-Output ('{{"error":"channel_unreadable","detail":"' +
            ($_.Exception.Message -replace '"', "'") + '"}}')
        exit 0
    }}
}}
$rows = @()
foreach ($e in $events) {{
    $row = @{{
        Id          = $e.Id
        RecordId    = [int64] $e.RecordId
        TimeCreated = $e.TimeCreated.ToUniversalTime().ToString('o')
        ProcessId   = $e.ProcessId
    }}
    try {{
        $xml = [xml] $e.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {{
            if ($d.Name) {{ $row[$d.Name] = $d.'#text' }}
        }}
    }} catch {{ }}
    $rows += [pscustomobject]$row
}}
ConvertTo-Json -Compress -Depth 4 -InputObject @{{
    records = @($rows); newest_record_id = $newestId
    filter_mode = $mode; filter_error = $filterError
}}
"""


def read_dns_events(
    max_events: int = 500,
    timeout_seconds: float = 30.0,
    powershell_path: str = "powershell",
    channel: str = CHANNEL,
    after_record_id: int = 0,
) -> "EventLogRead":
    """
    Read raw records from the DNS-Client event channel.

    Raises `DnsEventLogUnavailable` with the specific reason — absent,
    disabled, or unreadable by this account — because those are three
    different operator actions and collapsing them to "no DNS evidence"
    would hide which one applies.

    This half has never executed in CI: it needs Windows and an enabled
    channel. `parse_dns_events` holds everything testable.
    """
    if max_events < 1:
        raise ValueError("max_events must be at least 1")

    script = _PS_READ_EVENTS.format(
        channel=channel,
        max_events=int(max_events),
        after_record_id=max(0, int(after_record_id)),
    )
    try:
        proc = subprocess.run(
            [powershell_path, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError as exc:
        raise DnsEventLogUnavailable(
            f"PowerShell executable {powershell_path!r} not found; the DNS "
            "event channel cannot be read on this host."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise DnsEventLogUnavailable(
            f"Reading {channel} timed out after {timeout_seconds}s"
        ) from exc

    if proc.returncode != 0:
        raise DnsEventLogUnavailable(
            f"Reading {channel} failed (exit {proc.returncode}): "
            f"{(proc.stderr or '').strip()[:400]}"
        )

    raw = (proc.stdout or "").strip()
    if not raw:
        raise DnsEventLogUnavailable(f"Reading {channel} returned no output")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DnsEventLogUnavailable(
            f"Reading {channel} returned unparseable output: {raw[:200]}"
        ) from exc

    error = payload.get("error") if isinstance(payload, dict) else None
    if error == "channel_absent":
        raise DnsEventLogUnavailable(
            f"{channel} does not exist on this host, so there is no "
            "event-log alternative to the DNS cache."
        )
    if error == "channel_disabled":
        raise DnsEventLogUnavailable(
            f"{channel} exists but is disabled, which is the Windows "
            "default. While it is off it records nothing. Enabling it "
            "requires Administrator and is the operator's decision."
        )
    if error == "channel_unreadable":
        raise DnsEventLogUnavailable(
            f"{channel} is enabled but could not be read by this account: "
            f"{payload.get('detail', 'no detail reported')}"
        )

    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise DnsEventLogUnavailable(
            f"Reading {channel} returned no record list"
        )
    return EventLogRead(
        records=[r for r in records if isinstance(r, dict)],
        newest_record_id=_as_int(payload.get("newest_record_id")) or 0,
        requested_after=max(0, int(after_record_id)),
        batch_limit=int(max_events),
        filter_mode=str(payload.get("filter_mode") or "cold_start"),
        filter_error=str(payload.get("filter_error") or ""),
    )


def collect_dns_observations(
    source_id: Optional[str] = None,
    max_events: int = 500,
    after_record_id: int = 0,
    **kwargs: Any,
) -> tuple[list[dict[str, Any]], DnsEventParseReport, "EventLogRead"]:
    """
    Read and parse in one call, returning storage-shaped observations.

    The report travels with them: a caller that stores the rows without
    also surfacing what was skipped would present a partial read as a
    complete one.
    """
    read = read_dns_events(
        max_events=max_events, after_record_id=after_record_id, **kwargs
    )
    # Parse only what the bookmark has not already covered. On the
    # fallback path this is what keeps the read incremental; on the
    # filtered path it is a no-op.
    report = parse_dns_events(read.new_records())
    return (
        [obs.as_observation(source_id) for obs in report.observations],
        report,
        read,
    )

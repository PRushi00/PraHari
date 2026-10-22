<#
.SYNOPSIS
    PraHari — sample the DNS-Client event log to settle two open questions.

.DESCRIPTION
    Discovery (ADR-119) found the channel enabled and readable, and
    captured ONE event 3008 in full. The adapter (ADR-120) parses 3008
    on that basis and nothing else. Two questions remain open, and both
    need records this container cannot read:

      1. WHAT ARE 3006 AND 1001?
         Both appear in the channel. No field of either has been seen.
         The adapter counts them and refuses to parse them, because
         guessing here produces an attributed hostname — a wrong one.

      2. ARE EXTERNAL QUERIES CAPTURED AT ALL?
         The only 3008 observed was a lookup of `localhost`. That proves
         the channel records something; it does NOT prove it records a
         browser resolving a public name. Until an external QueryName
         appears here, PraHari must not claim browser DNS visibility.

    This script answers both by dumping every field of several records
    per event id, and by reporting whether any observed QueryName is
    external.

    READ-ONLY, like its predecessor. It enables nothing, clears nothing,
    changes no DNS setting, sends no DNS query of its own, and raises no
    privilege. Run it UNELEVATED: whether the collector's own account can
    read these records is part of what is being established.

.EXAMPLE
    # Generate some real external traffic first, then sample:
    powershell -ExecutionPolicy Bypass -File scripts\sample_dns_events.ps1 > dns-sample.txt
#>

[CmdletBinding()]
param(
    # Records to show per event id. Enough to see whether fields vary.
    [int] $PerEventId = 4,

    # How many recent records to scan when grouping by event id.
    [int] $ScanDepth = 400
)

$ErrorActionPreference = 'Continue'
$channel = 'Microsoft-Windows-DNS-Client/Operational'

function Write-Section($Title) {
    Write-Host ''
    Write-Host ('=' * 72)
    Write-Host "  $Title"
    Write-Host ('=' * 72)
}

Write-Host 'PraHari — DNS event sampling (read-only)'
Write-Host "Run at:  $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) UTC"

$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($me)
Write-Host ("  User: {0}   Elevated: {1}" -f $me.Name,
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))

# ─────────────────────────────────────────────────────────────────────
Write-Section 'Channel'

try {
    $log = Get-WinEvent -ListLog $channel -ErrorAction Stop
    Write-Host ("  enabled: {0}   records held: {1}" -f $log.IsEnabled, $log.RecordCount)
    if (-not $log.IsEnabled) {
        Write-Host '  DISABLED — nothing to sample. This script does not enable it.'
        return
    }
} catch {
    Write-Host "  Channel unavailable: $($_.Exception.Message)"
    return
}

try {
    $events = @(Get-WinEvent -LogName $channel -MaxEvents $ScanDepth -ErrorAction Stop)
} catch {
    Write-Host "  Not readable by this account: $($_.Exception.Message)"
    Write-Host '  That is a result: PraHari would be unable to read it either.'
    return
}

Write-Host ("  scanned: {0} record(s)" -f $events.Count)

# ─────────────────────────────────────────────────────────────────────
Write-Section 'Event ids present'

$groups = $events | Group-Object Id | Sort-Object Count -Descending
foreach ($g in $groups) {
    Write-Host ("  Id {0,-6} x{1}" -f $g.Name, $g.Count)
}

# ─────────────────────────────────────────────────────────────────────
Write-Section 'Every field, by event id'

# This is what the adapter needs in order to interpret 3006 and 1001.
# Field NAMES and ORDER matter to the parser; values are shown so the
# shape is unambiguous. A hostname is not a credential, and nothing in
# this channel is one.

foreach ($g in $groups) {
    Write-Host ''
    Write-Host ("  ───── Event Id {0} ({1} seen) ─────" -f $g.Name, $g.Count)
    $sample = @($g.Group | Select-Object -First $PerEventId)
    $index = 0
    foreach ($e in $sample) {
        $index++
        Write-Host ("    [{0}] TimeCreated = {1}" -f $index,
            $e.TimeCreated.ToUniversalTime().ToString('o'))
        Write-Host ("        ProcessId   = {0}" -f $e.ProcessId)
        try {
            $xml = [xml] $e.ToXml()
            $data = $xml.Event.EventData.Data
            if ($null -eq $data) {
                Write-Host '        (no EventData fields on this record)'
            } else {
                foreach ($d in $data) {
                    Write-Host ("        {0,-22} = {1}" -f $d.Name, $d.'#text')
                }
            }
        } catch {
            Write-Host "        (record XML unreadable: $($_.Exception.Message))"
        }
    }
}

# ─────────────────────────────────────────────────────────────────────
Write-Section 'Are external names captured?'

# The decisive question. A channel that only ever logs `localhost` and
# other local names gives PraHari nothing it can attribute a real
# connection with.

$names = @()
foreach ($e in $events) {
    try {
        $xml = [xml] $e.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name -eq 'QueryName' -and $d.'#text') { $names += [string]$d.'#text' }
        }
    } catch { }
}

$unique = @($names | Sort-Object -Unique)
Write-Host ("  QueryName values seen: {0} ({1} distinct)" -f $names.Count, $unique.Count)

# "Local" by structure, deliberately crude and stated as such: a name
# with no dot, or ending in a local suffix, is not evidence of external
# resolution. Anything else is reported as a candidate, not asserted.
$localish = '^(localhost|.*\.local|.*\.home|.*\.lan|.*\.internal|[^.]+)$'
$external = @($unique | Where-Object { $_ -notmatch $localish })

Write-Host ''
if ($external.Count -gt 0) {
    Write-Host ("  EXTERNAL NAMES PRESENT — {0} distinct:" -f $external.Count)
    foreach ($n in @($external | Select-Object -First 20)) {
        Write-Host ("    {0}" -f $n)
    }
    Write-Host ''
    Write-Host '  This settles question 2: the channel does record lookups of'
    Write-Host '  public names, so it is usable for attributing real connections.'
} else {
    Write-Host '  NO EXTERNAL NAMES in this sample.'
    Write-Host ''
    Write-Host '  Every QueryName looks local. That does NOT yet prove the channel'
    Write-Host '  cannot see external lookups — it may mean none happened while it'
    Write-Host '  was enabled, or that the browser used its own encrypted DNS and'
    Write-Host '  bypassed the Windows resolver entirely.'
    Write-Host ''
    Write-Host '  To distinguish those: browse to a few sites in your normal'
    Write-Host '  browser, run `Resolve-DnsName example.com`, then re-run this.'
    Write-Host '  If Resolve-DnsName appears but the browser does not, the browser'
    Write-Host '  is doing its own DNS and no host-side source will see it.'
}

# ─────────────────────────────────────────────────────────────────────
Write-Section 'What to do with this output'

Write-Host @'
  Send this whole output back. It settles the two things the adapter
  currently refuses to assume:

    1. what event ids 3006 and 1001 actually contain, so they can be
       interpreted instead of merely counted;
    2. whether external query names reach this channel at all, which is
       what browser DNS visibility depends on.

  Nothing on this machine was changed by running it.
'@

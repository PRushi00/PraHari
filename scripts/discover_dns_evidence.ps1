<#
.SYNOPSIS
    PraHari — what DNS evidence does THIS Windows machine actually offer?

.DESCRIPTION
    The operator's diagnostic showed the DNS Client service running, the
    resolvers configured as 1.1.1.1 and 8.8.8.8, and the cache holding
    ZERO entries. An empty cache does not establish that no DNS is
    happening: entries expire, the cache may be restricted, and
    encrypted DNS (DoH/DoT) never appears in it at all. Polling an empty
    cache more often cannot fix that — a different evidence source is
    needed (ADR-118).

    The obvious next source is the Windows DNS-Client event log. Writing
    a collector against it first would mean guessing at provider names,
    channel states, permissions and field shapes. This script finds out
    instead, on the machine that matters, and prints what it found.

    WHAT THIS SCRIPT DOES NOT DO, by design:
      * It does not ENABLE any event channel. An operational channel
        that is disabled is reported as disabled; turning it on is a
        change to the machine and is the operator's decision, not a
        script's side effect.
      * It does not flush the DNS cache, change a resolver, alter a
        firewall rule, or elevate privilege.
      * It sends no DNS query and no network traffic of its own.
      * It reads no message contents — only metadata about what evidence
        exists and whether it is readable.

    Everything it prints is read-only observation. Run it as the user
    PraHari's collector will run as, so the permission answers are the
    ones that will apply in practice.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\discover_dns_evidence.ps1

.EXAMPLE
    # Keep the output for the field-mapping step:
    powershell -ExecutionPolicy Bypass -File scripts\discover_dns_evidence.ps1 > dns-evidence.txt
#>

[CmdletBinding()]
param(
    # How many recent events to inspect when a readable channel is found.
    [int] $SampleSize = 5
)

$ErrorActionPreference = 'Continue'

function Write-Section($Title) {
    Write-Host ''
    Write-Host ('=' * 72)
    Write-Host "  $Title"
    Write-Host ('=' * 72)
}

function Write-Fact($Name, $Value) {
    Write-Host ("  {0,-34} {1}" -f $Name, $Value)
}

Write-Host 'PraHari — DNS evidence discovery (read-only)'
Write-Host "Run at:  $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) UTC"

# ─────────────────────────────────────────────────────────────────────
Write-Section 'Who is asking'
# The permission answers below are only meaningful alongside the identity
# they were obtained under.

$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($me)
Write-Fact 'User' $me.Name
Write-Fact 'Elevated (Administrator)' $principal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Fact 'PowerShell' $PSVersionTable.PSVersion
Write-Fact 'OS' (Get-CimInstance Win32_OperatingSystem).Caption

# ─────────────────────────────────────────────────────────────────────
Write-Section 'The cache PraHari reads today'

try {
    $cache = @(Get-DnsClientCache -ErrorAction Stop)
    Write-Fact 'Get-DnsClientCache' 'readable'
    Write-Fact 'Entries held now' $cache.Count
    if ($cache.Count -eq 0) {
        Write-Host '  An empty cache is not evidence that no DNS occurred.'
    }
} catch {
    Write-Fact 'Get-DnsClientCache' "NOT readable: $($_.Exception.Message)"
}

try {
    $svc = Get-Service -Name Dnscache -ErrorAction Stop
    Write-Fact 'DNS Client service (Dnscache)' $svc.Status
} catch {
    Write-Fact 'DNS Client service (Dnscache)' "not found: $($_.Exception.Message)"
}

# ─────────────────────────────────────────────────────────────────────
Write-Section 'Candidate event providers'

$providerNames = @(
    'Microsoft-Windows-DNS-Client'
    'Microsoft-Windows-DNSServer'
    'Microsoft-Windows-DNS-Server-Service'
)

foreach ($name in $providerNames) {
    try {
        $p = Get-WinEvent -ListProvider $name -ErrorAction Stop
        Write-Fact $name 'present'
        foreach ($log in $p.LogLinks) {
            Write-Host ("      channel: {0}" -f $log.LogName)
        }
    } catch {
        Write-Fact $name 'absent'
    }
}

# ─────────────────────────────────────────────────────────────────────
Write-Section 'Channel state and readability'

# The operational channel is the one worth collecting from. It is
# commonly present but DISABLED. That is reported, never changed.

$channels = @(
    'Microsoft-Windows-DNS-Client/Operational'
    'Microsoft-Windows-DNSServer/Analytical'
)

$readable = @()

foreach ($channel in $channels) {
    Write-Host ''
    Write-Host "  [$channel]"
    try {
        $log = Get-WinEvent -ListLog $channel -ErrorAction Stop
        Write-Fact '  enabled' $log.IsEnabled
        Write-Fact '  log mode' $log.LogMode
        Write-Fact '  records held' $log.RecordCount
        Write-Fact '  max size (bytes)' $log.MaximumSizeInBytes

        if (-not $log.IsEnabled) {
            Write-Host '    DISABLED. This script does not enable it: that is a'
            Write-Host '    change to the machine and is the operator''s decision.'
            Write-Host '    To enable it yourself (Administrator):'
            Write-Host "      wevtutil sl `"$channel`" /e:true"
            continue
        }

        if ($log.RecordCount -eq 0) {
            Write-Host '    Enabled but empty. Browse to something and re-run.'
            continue
        }

        # Can THIS user actually read it? Enabled does not imply readable.
        try {
            $events = @(Get-WinEvent -LogName $channel -MaxEvents $SampleSize -ErrorAction Stop)
            Write-Fact '  readable by this user' 'yes'
            Write-Fact '  sampled' $events.Count
            $readable += $channel
        } catch {
            Write-Fact '  readable by this user' "NO: $($_.Exception.Message)"
        }
    } catch {
        Write-Fact '  present' "no: $($_.Exception.Message)"
    }
}

# ─────────────────────────────────────────────────────────────────────
Write-Section 'What a record actually contains'

# This is the part the adapter needs. Field names and shapes are read
# from a real record rather than from documentation, because the
# collector will parse THESE, not the documented ideal.

if ($readable.Count -eq 0) {
    Write-Host '  No readable DNS event channel on this machine.'
    Write-Host ''
    Write-Host '  That is a result, not a failure. It means host DNS evidence'
    Write-Host '  must come from the cache (which may be empty), or from a'
    Write-Host '  network sensor that observes the queries, or not at all.'
    Write-Host '  PraHari must report the absence rather than infer hostnames.'
} else {
    foreach ($channel in $readable) {
        Write-Host ''
        Write-Host "  [$channel]"
        $events = @(Get-WinEvent -LogName $channel -MaxEvents $SampleSize -ErrorAction SilentlyContinue)

        $byId = $events | Group-Object Id | Sort-Object Count -Descending
        Write-Host '    event ids seen in this sample:'
        foreach ($g in $byId) {
            Write-Host ("      Id {0,-6} x{1}" -f $g.Name, $g.Count)
        }

        $first = $events | Select-Object -First 1
        if ($null -ne $first) {
            Write-Host ''
            Write-Host '    first record, field by field:'
            Write-Fact '      Id' $first.Id
            Write-Fact '      TimeCreated (UTC)' $first.TimeCreated.ToUniversalTime().ToString('o')
            Write-Fact '      ProcessId' $first.ProcessId
            try {
                $xml = [xml] $first.ToXml()
                foreach ($d in $xml.Event.EventData.Data) {
                    # Names and order matter to the parser; values are
                    # printed so the shape is unambiguous (a hostname is
                    # not sensitive, and nothing here is a credential).
                    Write-Host ("        {0,-24} = {1}" -f $d.Name, $d.'#text')
                }
            } catch {
                Write-Host "        (could not parse record XML: $($_.Exception.Message))"
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────
Write-Section 'What to do with this output'

Write-Host @'
  Send this whole output back. It determines three things that cannot be
  guessed from here:

    1. whether a DNS event channel exists and is enabled on your machine;
    2. whether the account PraHari runs as may read it without elevation;
    3. the exact event ids and field names a collector must parse.

  Nothing on this machine was changed by running it. If a channel is
  reported DISABLED and you want it collected, enabling it is a decision
  for you — the command is printed above, and it needs Administrator.
'@

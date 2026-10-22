# PraHari — Monitoring Expansion Plan

**Written 22 Oct 2026.** This plan responds to a proposal to turn PraHari
into a host-and-network monitoring dashboard. It adopts most of it, and
departs from it in one place that matters.

---

## The decision that shapes everything

The proposal opened with *"PraHari should become a host and network
monitoring dashboard"* and gave five navigation areas — Overview,
Devices, Traffic, Connections, System — with forecasting moved to
"secondary tools or advanced views".

**That is rejected.** `README.md` defines PraHari as *"Causal Future
Threat Forecasting"*, and the problem statement it answers is a
forecasting problem. Monitoring dashboards are a crowded, well-solved
category; a forecaster with a research gate that **refuses** when the
data cannot support a claim is the part of this system that is unusual.
Demoting it would trade the distinctive thing for a commodity one.

**Adopted instead: two peer workflows.**

| Group | Pages | What the operator is doing |
|---|---|---|
| **Monitor** | Overview, Live Telemetry, Devices, Events Explorer, Analytics, CSV Import, Stream & Replay | Seeing what is happening and what was collected |
| **Forecast** | Feasibility, Threat Forecasting, Investigation | Asking what is likely to happen, and why it was said |
| Operate | System Health, Administration, Audit & Security | Running the thing |

Monitor and Forecast are **peers**. Operate is a third group because
settings and audit are a different kind of activity, not a lesser one.
Nothing is removed and no page becomes unreachable.

---

## What the proposal asked for that already exists

Three of its five phases are substantially built. Checked in the source
before this plan was written, not assumed:

| Proposal | Already in the repository |
|---|---|
| Phase 4 — "device registration and authenticated agent ingestion" | `POST /api/v1/sources` registers a source. `local_producer_owning` plus the ADR-090 reservation guard already prevent a device becoming trusted by claiming an id it does not own |
| Phase 5 — "network sensor integration" | `adapters/json_stream.py` parses **Zeek `conn.log`** and **Suricata EVE**. 989/989 real Zeek records have been accepted through it |
| "DNS visibility" | `services/enrichment.py` reads the Windows DNS client cache, sends no query, needs no elevation, **refuses reverse DNS** (a PTR names the address's owner, not the hostname requested), and carries method, evidence timestamp, competing candidates and confidence on every attribution |

So the work is mostly interface and one real collector, not new
architecture.

---

## The one capability genuinely missing

**DNS evidence from the Windows DNS-Client event log, rather than the
cache.**

The operator's diagnostic showed the DNS Client service running,
resolvers configured as `1.1.1.1` and `8.8.8.8`, and **zero** cached
entries. The proposal's reading is correct and PraHari already says it:
an empty cache does **not** establish that no DNS is happening. Entries
expire, the cache may be restricted, and encrypted DNS (DoH/DoT) never
appears in it at all.

Polling an empty cache more often cannot fix that. A different evidence
source is needed.

### Sequencing, and why discovery comes first

A collector must not be written against event fields nobody has
confirmed exist on the target machine. The order is therefore:

1. **Discovery** — `scripts/discover_dns_evidence.ps1` reports, on the
   operator's own Windows machine, which DNS providers are present,
   whether the operational channel is enabled, whether the current user
   may read it, and what a sample record actually contains. It is
   **read-only**: it enables no channel, changes no DNS setting, flushes
   no cache and raises no privilege.

   **Done, 22 Oct 2026 — twice, and the second run reversed the first
   (ADR-121).** A cold read of a freshly-enabled circular channel found
   only `localhost`; a read taken after real browsing found **59
   distinct external names in 7.6 minutes**, browser lookups included.
   The channel retains under 8 minutes, so the first result was a
   property of when it was sampled, not of the host. ADR-119's
   conclusion below is superseded.

   **Superseded (ADR-119).** On
   Windows 11 Home, unelevated: the `Microsoft-Windows-DNS-Client`
   provider is present, its Operational channel is **disabled** (the
   Windows default), and the cache holds zero entries. So **no host DNS
   evidence exists on that machine at all**, and no field could be
   inspected. Steps 2 and 3 are blocked until the channel is enabled —
   an Administrator action and the operator's decision — and discovery
   is re-run.
2. **Field mapping** — written from that output, not from documentation.
3. **Adapter + tests** — a `windows_dns_events` adapter against the
   confirmed shape, with the same refusal discipline as every other
   adapter: a field the source cannot supply is stored null and flagged,
   never estimated.

Step 1 runs on the operator's machine. Steps 2 and 3 can then be done
anywhere.

---

## What must never be rendered

The proposal's own device mock-up shows per-device traffic —
`OnePlus-Phone ↑420 MB ↓210 MB`, `Smart-TV ↑310 MB` — for devices with
no agent and no sensor. Its text forbids exactly this; its picture does
it anyway.

**A device PraHari has not collected from has no traffic figures.** The
Devices view shows a registered device's monitoring method and its
evidence state, and where there is no evidence it says so. Knowing an
address is not monitoring, and an empty state is the honest render, not
a gap to fill with plausible numbers.

This is the same rule the rest of the application already follows:
`not measured` is never shown as zero, and guided mode may not defer a
caveat (ADR-115).

---

## Phases

| | Work | Where it can be done | State |
|---|---|---|---|
| 1 | Two peer nav groups | here | ✅ **done** (ADR-118) — every route reachable, verifier green |
| 2 | Two-column Overview: this host / other devices | here | ✅ **done** (ADR-118) — real host counts; no registered device renders an explicit empty state, never invented traffic |
| 3 | Device registration UI over the existing source API | here | ✅ **done** (ADR-118) — monitoring method recorded; inventory-only distinguishable; exposed and closed an unguarded `POST /sources` in central mode |
| 4 | DNS evidence discovery script | **operator's Windows machine** | ✅ **done** (ADR-119) — ran clean, changed nothing |
| 4b | Enable the channel, re-run discovery | operator's decision | ✅ **done** (ADR-121) — 17 event ids field-mapped; **59 external names in 7.6 min**, reversing ADR-119 |
| 5 | `windows_dns_events` adapter | here | ✅ **done** (ADR-120, ADR-121) — event 3008 only; 3006 and 1001 counted, not parsed |
| 6 | Traffic Explorer with explicit direction | here | ✅ **done** (ADR-122) — inbound/outbound/local/unknown as a labelled inference; `unknown` filterable |
| 7 | DNS Activity view | here | ✅ **done** (ADR-122) — every row carries its evidence source; empty store explained, not blank |
| 8 | Per-device traffic | **needs an authorized device** | ⛔ **blocked** — needs an agent on the device, or a sensor that can see its traffic. Neither exists |
| 9 | Second device sends distinguishable telemetry | **needs a second machine** | ⛔ **blocked** — the registration path is built; nothing has registered through it |
| 10 | Network sensor reconciled against sensor logs | **needs an observation point** | ⛔ **blocked** — Zeek parsing works (989/989 accepted), but from one source on a Docker bridge, and the container is gone |

**Everything that needs only work in this repository is done.** Rows 1
to 7 are complete and verified. Rows 8 to 10 are blocked on physical
things this container does not have: a second machine, an authorized
agent, or an observation point that can see the traffic. No amount of
work here closes them, and building a convincing-looking interface for
data that does not exist is the one thing this project must not do.

**The alternative is already working.** Zeek is wired into the JSON
stream path and has accepted 989/989 real records. A sensor observes DNS
queries on the wire — evidence neither host source currently provides —
and needs no change to the Windows machine at all. Where DNS visibility
is the goal rather than host-only collection, that is the shorter path.

---

## Not established

Nothing in this plan has been measured. It is a sequence and a set of
constraints, and the only claims of fact in it — about what already
exists — were read in the source on 22 Oct 2026 and are cited above by
file.

Phase 6 in particular should not be scheduled: per-device traffic needs
an authorized agent or an observation point that can actually see the
traffic, and neither exists yet.

# Dataset Acquisition and Audit Workflow

Blueprint §8 requires recorded provenance, hashes, schema and leakage
controls for any dataset used in evaluation.

**Status: no external dataset has been acquired.** The import and audit
workflow below is implemented and tested; the acquisition itself is
outstanding and is a deliberate user decision, because it involves licence
acceptance and a multi-gigabyte download.

Nothing here downloads anything automatically.

---

## Why no dataset is bundled

| Reason | Detail |
|---|---|
| **Licence** | CSE-CIC-IDS2018 and CTU-13 carry terms that a person must read and accept. An automated agent cannot meaningfully accept a licence on your behalf. |
| **Size and cost** | CSE-CIC-IDS2018 is tens of gigabytes. Downloading it unprompted could incur bandwidth cost and fill the disk. |
| **Authorisation** | The safety boundary forbids silently fetching large external resources. |

So the project ships the *workflow*, not the data.

---

## What locally collected telemetry cannot do

This matters more than the dataset question: **live Windows telemetry
cannot train or validate a forecaster, and never will on its own.**

- It carries **no incident labels**. Nothing in a TCP connection table says
  "this was an attack".
- Unlabelled traffic is **not** benign. PraHari refuses to treat it as a
  negative example (see ADR-021), so it yields zero usable windows.
- Without labels there is no target, so there is nothing to learn or to
  measure against.

The research gate therefore refuses live-only data, correctly. Measured
against a copy of the operational database (3,469 live events):

```
state: missing_or_invalid_labels
labelled=0  positives=0  negatives=0   can_train=False
POST /api/v1/forecast/train -> HTTP 409  forecasting_blocked_by_research_gate
```

Note the state: there **is** enough data over a long enough period. What is
missing is any label, so there is no target to learn. More collection
cannot fix that.

---

## Acquisition checklist (operator-performed)

Record each of these before a dataset is used:

| Field | Why |
|---|---|
| Source URL and version | Reproducibility; datasets are revised |
| Licence and terms, acceptance date | Legal basis for use |
| Acquisition date, acquirer | Provenance chain |
| Exact file list | Partial downloads change results silently |
| **SHA-256 per file** | Proves the bytes evaluated are the bytes described |
| Row semantics | Packets, flows, aggregates or derived features? |
| Timestamp timezone and precision | Window construction depends on it |
| Label scope | Flow-level, scenario-level, host-level or event-level |
| Known preprocessing artifacts | e.g. duplicated headers mid-file |

Keep this alongside the experiment manifest, not in prose only.

---

## Import and audit workflow (implemented)

1. **Import** through the canonical CSV adapter:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/import/csv/file \
  -F "file=@flows.csv" -F "source_id=cicids2018" -F "data_category=historical_import"
```

Validation rejects malformed rows with explicit reasons rather than
coercing them; the summary reconciles accepted + rejected = total.

2. **Audit** the resulting dataset:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/research/audit?source_id=cicids2018"
```

Reports temporal monotonicity, label balance and ground-truth presence,
provenance integrity, and data-quality defects (with source limitations
and synthetic markers excluded from the defect count).

3. **Check readiness** before training:

```bash
curl "http://127.0.0.1:8000/api/v1/forecast/readiness?source_id=cicids2018"
```

4. **Train**, which refuses if the gate is unmet or no leakage-free split
   exists, then **capture a manifest**:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/experiments/capture \
  -H "Content-Type: application/json" \
  -d '{"experiment_id":"cicids2018-baseline","source_id":"cicids2018"}'
```

5. **Verify reproduction** at any later point:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/experiments/cicids2018-baseline/replay
```

Replay fails closed on a changed dataset fingerprint, schema version or
feature set.

---

## Leakage controls applied automatically

| Control | Implementation |
|---|---|
| Chronological split | Training strictly precedes evaluation |
| Boundary purge | `ceil((W+L+H)/S)` windows dropped from the training side |
| No instance reassignment | Windows are never moved across the boundary to balance classes |
| Negative-label validity | `y=0` only when the horizon was observed and labelled |
| Refusal over inflation | Evaluation is refused when no honest split exists |
| Frozen protocol | Window and split parameters recorded in the manifest before results are read |

**Still your responsibility** when importing an external dataset:

- Exclude post-event columns and scenario metadata that leak the target.
- Decide whether rows are flows or packets, and whether scenario- or
  host-aware holdouts are needed beyond chronological splitting.
- Confirm that negative examples have a complete observation window in the
  source data, not merely in PraHari's windowing.

---

## Keeping synthetic data separate

| Category | Meaning |
|---|---|
| `live_telemetry` | Observed on this host |
| `historical_import` | Imported from a file |
| `historical_replay` | Replayed historical records |
| `synthetic_demo` | **Generated.** Never evidence of real-world performance |
| `test_fixture` | Test data only |

The category travels on every record, the analysis derives its own category
from the data, and the experiment manifest records the full breakdown —
so a result computed on synthetic data cannot be presented as a real one.

Every metric produced by this project so far comes from `synthetic_demo`
data. It demonstrates the pipeline functions. It is **not** evidence of
forecasting effectiveness.

---

## Pre-ingestion hardening (implemented, dataset NOT acquired)

**Nothing below involved downloading a dataset, accepting a licence, or
contacting any remote service.** The workflow is built and tested against
synthetic fixtures the test suite writes; the corpus itself has not been
acquired, inspected, imported or validated.

### Research store isolation — fail closed

Benchmark corpora never share a database with operational telemetry.

```bash
export PRAHARI_RESEARCH_DATABASE_URL=sqlite:///./research/benchmark.db
```

`GET /api/v1/research/import/status` reports whether a store is configured.
A research import is **refused before any row is read** when the setting is
missing, is not a supported SQLite target, resolves to the operational
database (including through `..` or the legacy `backend/prahari.db`), or
points at a directory that does not exist. There is no fallback.

The general `POST /import/csv/*` endpoints additionally refuse
`data_category=historical_import` when the target is the operational
database, so a mis-aimed benchmark import cannot contaminate the only copy
of genuine local observations.

### Explicit ingestion policy

`POST /api/v1/research/import/csv` requires the operator to state what
cannot be inferred from the bytes. Dry run by default.

| Setting | Why it must be stated |
|---|---|
| `timestamp_format` | `auto` **rejects** a date readable as both `dd/mm/yyyy` and `mm/dd/yyyy`. Guessing silently reorders the dataset, and chronological order is what every window, split and purge depends on |
| `source_timezone` | Left `null` when the publisher documents none. Recorded as unknown in the manifest; naive timestamps are stored UTC-aware and flagged. Never silently called UTC |
| `duration_unit` | CICFlowMeter `Flow Duration` is **microseconds**; the canonical schema is **seconds**. `unknown` means the column is not imported — an unconverted value is a 10⁶× error nothing downstream would catch |
| `require_bidirectional_counts` | `packets`/`bytes_total` are documented as totals. A forward-only file leaves them empty rather than reporting half a measurement under a total's name |

### Row handling

- **Repeated header rows** are detected and skipped. Left in, one yields
  `label="Label"`, which the attack rule ("anything not benign") scores as
  an **incident** — fabricated positives in the target.
- **Numeric values** are classified as missing, malformed, non-finite
  (`Infinity`/`NaN`, which CICFlowMeter emits in rate columns) or
  invalid-negative, each counted per column. A recorded `0` stays `0`.
- **Quality counts reconcile**: `rows_read = accepted + rejected +
  skipped_header + skipped_blank`, asserted by test.

### Deterministic identity

Event ids are derived from the **source file's SHA-256**, the row's index
in it, and the row's normalised content. Re-importing the same file
persists nothing new.

File+row identity is used rather than content alone deliberately: two
genuinely distinct flows can carry identical values, and collapsing them
would delete real observations. Near-duplicates are therefore **counted and
kept**, not dropped. The trade-off is that the same corpus re-exported with
different bytes is treated as a different dataset — the conservative
direction.

### Import manifest

Every import produces a manifest recording the dataset name and release the
operator supplied, the source filename (basename only — an absolute path
would leak the operator's home directory), its SHA-256 and size, the
adapter and schema versions, the full policy applied, unit conversions,
field mapping, the label policy, and the complete quality summary. Written
atomically; the same bytes map to the same manifest file.

> A SHA-256 proves **byte identity** only. It does not prove authenticity,
> publisher provenance, or that the labels are correct. The manifest is a
> durable record on disk, not a tamper-proof one, and is not described as
> immutable.

### Provenance-aware training

`POST /forecast/train` filters on `data_category` — the authoritative
provenance field — not only `source_id`, which is a name an operator chose.
A selection spanning benchmark, live and generated data is **refused**
unless `allow_mixed_provenance=true`, and the composition is recorded when
it is allowed.

### Coverage honesty

`GET /forecast/coverage` reports selected count against total matching
count, the truncation flag, the selection strategy, the time range, and the
source / category / label composition.

This matters at benchmark scale: `list_events` applies `ORDER BY
observed_at DESC LIMIT n`, so asking for 100,000 events from a multi-million
row corpus previously returned the newest 100,000 — the tail of the final
capture day — with nothing saying so. Selection is now returned in
chronological order and truncation is stated.

### Forecasting-validity controls

- **Ongoing-attack windows** — those whose *observation* period already
  contains attack-labelled events — are counted
  (`windows_with_attack_in_observation`) and can be excluded. Predicting
  "attack soon" from "attack now" is detection; reporting it as forecasting
  overstates what was shown.
- **Persistence baseline** (`baseline_persistence`): "attack now ⇒ attack
  next", fitted on the observation-window indicator only, which describes
  `[t-W, t)` and so uses no future label. On bursty data it is strong — in
  one recorded synthetic run it reached PR-AUC 0.755, **above the LSTM's
  0.751**. Any model that cannot beat it has demonstrated nothing.

### What remains outstanding

| Item | Status |
|---|---|
| Dataset acquisition | **Not done, not authorized.** Requires reading and accepting the publisher's terms |
| Licence acceptance | **Not done.** No terms accepted on the operator's behalf |
| Real schema validation | **Not possible here** — no file has been inspected |
| End-to-end evaluation on a real corpus | **Not done** |
| Timezone of the source timestamps | **Unknown** — treated as unknown, not assumed |
| Episode identifiers | **Not implemented.** Splitting is time-blocked and chronological; episode-aware holdout would need episode boundaries the current schema does not carry |

---

## Publisher facts, read on 17 Oct 2026

Read from the publishers' public pages only. **Nothing was downloaded, no
account was created and no terms were accepted.** Where a page was silent,
this says so instead of filling the gap. Re-read the pages at acquisition
time: terms can change.

### CSE-CIC-IDS2018 (https://www.unb.ca/cic/datasets/ids-2018.html)

| Item | What the page states |
|---|---|
| Licence | **No named licence.** The page says the dataset may be redistributed, republished and mirrored in any form, provided use cites the dataset and links its AWS page |
| Citation | Sharafaldin, Lashkari and Ghorbani, ICISSP 2018 |
| Access | AWS S3 bucket `cse-cic-ids2018`; the page describes syncing with the AWS CLI (`--no-sign-request`). No registration mentioned. Plain HTTPS also works - see below |
| Size | **Not stated** |
| Contents | Per-day PCAPs and Windows/Ubuntu event logs per machine; CICFlowMeter-V3 CSV flow features ("more than 80"; one section says 83) |
| Labels | Assigned from the attack schedule plus source/destination IPs, ports and protocol |
| Time zone | **Not stated.** Treat as unknown until checked against the PCAPs |

Implications for PraHari:
- The AWS CLI is not required: the bucket is readable over plain HTTPS
  (verified, see below). The download itself is large and needs explicit
  approval.
- Labels derive from an attack *schedule*. Blueprint section 7 forbids
  equating a scenario schedule with compromise, so these labels are
  `dataset_ground_truth` under the dataset's own rules and nothing
  stronger. The structured target's `not_equivalent_to` list says so.
- `research_csv` requires `Src IP` and `Dst IP` columns. Verify on
  acquisition that every per-day CSV actually contains them; a file
  without them will be rejected row by row, not silently mis-mapped.

### CTU-13 (https://www.stratosphereips.org/datasets-ctu13)

| Item | What the page states |
|---|---|
| Licence | **Not stated** on the page |
| Citation | Garcia, Grill, Stiborek and Zunino, "An empirical comparison of botnet detection methods", Computers and Security 45 (2014) 100-123 |
| Access | One compressed tar archive, or each of the 13 scenarios separately; a mega.nz mirror exists, the main site is described as authoritative |
| Size | Full archive 1.9 GB |
| Contents | Botnet-only PCAPs (the full capture is withheld for privacy), labelled bidirectional Argus flow files, and the malware executable for each scenario |
| Labels | Background, Botnet (including C&C) and Normal, assigned by manual analysis |
| Time zone | **Not stated** |

Implications for PraHari:
- **The dataset distributes each scenario's malware executable.** Acquiring
  the files that include them means
  handling malware on the host, which needs explicit approval and
  isolation, quite apart from the licence question.
- No licence is stated. Absence is not permission: ask the publisher or
  confirm terms before use.
- **Label mapping is mandatory and not implemented.** PraHari's attack
  rule treats any label other than benign/normal/unlabeled as an attack,
  so raw CTU-13 labels would make Background traffic positive. Background
  must not become a negative either: it is not evidence of benignity. The
  NetFlow adapter discards labels on purpose, so routing CTU-13 through it
  yields unlabelled events - safe, but unusable for supervised work. A
  CTU-13 importer needs the real label strings in hand; none was written
  against strings not yet seen (ADR-072).

### What must be approved or supplied before real-data validation

1. Choice of corpus, and confirmation of its terms by the operator.
2. Approval of the download (size, bandwidth, disk) and of any tool it
   needs.
3. For CTU-13, approval to hold malware samples, and where.
4. A dedicated research store (`PRAHARI_RESEARCH_DATABASE_URL`); imports
   are refused without one, and the operational databases are never used.
5. For CTU-13, a label mapping reviewed against the actual files.

Then the existing pipeline runs unchanged: import under an explicit
policy, audit, manifest with dataset hashes, chronological purged split,
the baseline/logistic/forest/LSTM comparison, replay.

---

## Compatibility verified without downloading (17 Oct 2026, ADR-088)

The processed CSVs of CSE-CIC-IDS2018 were checked against PraHari's
importer **without downloading the dataset**. The public bucket's file
listing was read, then only the first 3,000 bytes of each file - its
header row and one data row - were fetched by HTTP range request, held in
memory and discarded. 30 KB in total was read; nothing was written to disk.

**Access needs no AWS CLI.** The bucket is public over plain HTTPS
(`https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/`), and range
requests return `206 Partial Content`. This corrects the earlier note that
the CLI must be installed.

| File (`Processed Traffic Data for ML Algorithms/`) | Size | Columns | `Src IP` / `Dst IP` | Importable today |
|---|---|---|---|---|
| Wednesday-14-02-2018 | 358 MB | 80 | **absent** | no |
| Thursday-15-02-2018 | 376 MB | 80 | **absent** | no |
| Friday-16-02-2018 | 334 MB | 80 | **absent** | no |
| **Thuesday-20-02-2018** (sic) | **4,055 MB** | **84** | **present** | **yes - all 12 mapped columns present** |
| Wednesday-21-02-2018 | 329 MB | 80 | **absent** | no |
| Thursday-22-02-2018 | 383 MB | 80 | **absent** | no |
| Friday-23-02-2018 | 383 MB | 80 | **absent** | no |
| Wednesday-28-02-2018 | 209 MB | 80 | **absent** | no |
| Thursday-01-03-2018 | 108 MB | 80 | **absent** | no |
| Friday-02-03-2018 | 352 MB | 80 | **absent** | no |

Total 6.89 GB. Observed in every file: day-first timestamps
(`14/02/2018 08:31:01`, so `timestamp_format=day_first`), first-row label
`Benign`, and flow durations consistent with CICFlowMeter's microseconds.
The time zone is still unstated by the publisher.

The importer requires source and destination addresses, and two of the
twelve features count distinct addresses, so **nine of ten days would have
every row rejected.** Only Tuesday 20-02-2018 is usable as-is. The
publisher schedules two attacks that day: **DDoS-LOIC-HTTP 10:12-11:17**
and **DDoS-LOIC-UDP 13:13-13:32**, no time zone stated.

**What that supports.** One day, two episodes, one scenario. With a
default 70 % chronological split of a day that starts at 08:34, both
episodes would very likely fall in training and the test period would hold
no positives, so its metrics could not be interpreted. A split near 50 %
would train on the HTTP flood and test on the UDP flood: a real but narrow
result about one host and two attack variants. Cross-scenario
generalisation is not possible with one day.

**CIC-IDS2017** (five days, 14 scheduled attack types, labelled flows that
the publisher describes as including addresses and timestamps, citation-only
terms) is a better fit on paper. Its download is gated by a form requiring
name, email, organisation, job title and country. That is the operator's to
submit, so its column layout is **unverified**.

### Options, in order of cost

1. **Tuesday 20-02-2018 only (4.05 GB, no code change).** Real labels, end
   to end, with the narrow result described above. Needs approval of the
   download.
2. **Register for CIC-IDS2017**, then verify its headers the same way
   before downloading anything large.
3. **Accept flows without addresses** to unlock the other nine 2018 days.
   This is a research-design change, not a fix: the two address-count
   features would be unmeasured, so the feature schema - and comparability
   with any address-bearing run - changes. It needs an explicit decision.

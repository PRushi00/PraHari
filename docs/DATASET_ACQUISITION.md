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

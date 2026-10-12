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

The research gate therefore refuses live-only data, correctly. Verified:

```
state: insufficient_data
labelled=0 positives=0 negatives=0  can_train=False
POST /api/v1/forecast/train -> HTTP 409
```

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

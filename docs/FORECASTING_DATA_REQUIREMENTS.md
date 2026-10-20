# Forecasting Data Requirements

What a labelled dataset must contain for PraHari's forecasting pipeline to
produce a real, defensible result, and what that result would mean. Every
statement below is derived from the code that enforces it; file references
are given so each can be checked.

**Status (17 Oct 2026): no labelled dataset has been acquired. Nothing here
has been run against real data.** See `DATASET_ACQUISITION.md` for
publisher terms and the approvals needed before acquiring one.

---

## 1. The prediction target

Defined in `backend/app/research/target.py`
(`prahari.attack_label_in_horizon`, version 1.1.0) and recorded,
fingerprinted, in every experiment manifest.

> At prediction time **t**, using only flows observed in **[t − W, t)**
> that had *arrived* by t, predict whether **any flow carrying an attack
> label** occurs in the horizon **[t + L, t + L + H)**.

| Parameter | Default | Meaning |
|---|---|---|
| W, observation window | 60 s | Features come from this interval |
| L, lead time | 30 s | Gap between prediction and horizon; the warning's head start |
| H, horizon | 60 s | The interval whose labels decide y |
| S, stride | 15 s | Spacing between consecutive prediction times |

- **Positive (y = 1):** at least one flow in the horizon has an attack
  label. A label is an attack label when it is non-empty and, lower-cased
  and trimmed, is **not** `benign`, `normal` or `unlabeled`
  (`feature_extractor.py`).
- **Negative (y = 0):** only when the horizon holds at least one observed
  flow, none of them an attack, and at least one of them labelled
  (`require_labelled_horizon`). Any other window is **excluded**, never
  labelled 0: an empty horizon is a capture gap, and an unlabelled one is
  unknown.
- **What y is not:** scenario start, first malicious flow, compromise or a
  confirmed incident. It forecasts *the dataset's labels*, under the
  dataset's labelling rules.

## 2. The file format the importer accepts

The research importer (`backend/app/adapters/research_csv.py`) reads a CSV
shaped like **CICFlowMeter-V3** output, one row per flow. A header row is
required. Column names are matched against these spellings:

| Field | Accepted column names | Required | Notes |
|---|---|---|---|
| timestamp | `Timestamp`, `timestamp` | **yes** | Flow start. Format and time zone must be declared (§3) |
| src_ip | `Src IP`, `Source IP`, `src_ip` | **yes** | Valid IPv4/IPv6; otherwise the row is rejected |
| dst_ip | `Dst IP`, `Destination IP`, `dst_ip` | **yes** | Same |
| src_port | `Src Port`, `Source Port`, `src_port` | no | 0-65535 |
| dst_port | `Dst Port`, `Destination Port`, `dst_port` | no | 0-65535; a feature input |
| protocol | `Protocol`, `protocol` | no | IANA number or name (6 = TCP, 17 = UDP) |
| duration | `Flow Duration`, `flow_duration` | no | Unit must be declared (§3) |
| fwd_packets | `Tot Fwd Pkts`, `Total Fwd Packets`, `tot_fwd_pkts` | no | |
| bwd_packets | `Tot Bwd Pkts`, `Total Backward Packets`, `tot_bwd_pkts` | see §3 | |
| fwd_bytes | `TotLen Fwd Pkts`, `Total Length of Fwd Packets`, `totlen_fwd_pkts` | no | |
| bwd_bytes | `TotLen Bwd Pkts`, `Total Length of Bwd Packets`, `totlen_bwd_pkts` | see §3 | |
| label | `Label`, `label` | **for training** | Any text. Empty means unlabelled |

Rows missing a required field, or with an invalid address, timestamp or
numeric value, are **rejected and counted by reason**, never repaired.
Exact duplicate rows and same-identity rows are reported. A header row
repeated mid-file, a known CICFlowMeter artefact, is skipped and counted.

Labels imported from the file are recorded as `dataset_ground_truth`. Rows
without a label are `unlabeled`.

## 3. What the operator must declare (`ResearchCsvPolicy`)

| Setting | Values | Why |
|---|---|---|
| `timestamp_format` | `auto`, `day_first`, `month_first`, `iso` | `03/04/2018` is ambiguous; under `auto` such a row is rejected (`ambiguous_date_format`) rather than guessed |
| `source_timezone` | an IANA zone, or unset | Unset is recorded as **unknown** and flagged, never assumed to be UTC |
| `duration_unit` | `seconds`, `milliseconds`, `microseconds`, `unknown` | CICFlowMeter reports microseconds; a wrong unit corrupts every rate |
| `require_bidirectional_counts` | true (default) | Forward-only counts are not totals. With true, when the backward columns are absent the byte and packet totals are left **empty** (unmeasured) rather than filled with forward-only values; the rows are still imported |
| `max_records` | default 1,000,000 | Truncation is reported, never silent |

## 4. How much data, and of what kind

From `backend/app/research/readiness.py` and `forecaster.py`. These are
minimums for the pipeline to *run*, not for a result to be meaningful.

| Requirement | Minimum |
|---|---|
| Events | 200 |
| Time span | 1,800 s (30 min) of observation |
| Labelled events | 50 |
| Attack-labelled events | 10 |
| Benign-labelled events | 10 |
| Test-set windows for interpretable metrics | 20 |

A meaningful result needs far more: enough separate attack **episodes**
that a chronological split leaves several in the test period, and benign
traffic labelled densely enough that horizons qualify as negatives
(§1). With the default 60 s horizon, every negative window needs at least
one benign-labelled flow inside its minute.

Label provenance (`backend/app/research/label_policy.py`):
- **One declared provenance per experiment.** Corpus labels are never
  merged with detector alerts or analyst annotations.
- **Model predictions are never accepted as labels.**
- Synthetic labels (`synthetic_rule`) are classed `synthetic_only`, and the
  manifest says the result establishes nothing about real-world
  performance.

## 5. What the model sees

Twelve features per window (`FEATURE_NAMES`, `feature_extractor.py`), read
from these flow fields only: `src_ip`, `dst_ip`, `dst_port`, `protocol`,
`bytes_total`, `packets`, `duration`.

`flow_count`, `distinct_src_ips`, `distinct_dst_ips`, `distinct_dst_ports`,
`total_bytes`, `avg_bytes_per_flow`, `total_packets`, `avg_packets_per_flow`,
`tcp_ratio`, `udp_ratio`, `avg_duration`, `byte_rate_per_sec`.

No payload, no host data, no label-derived feature. Labels and every
post-window field are excluded by construction.

## 6. Splitting and generalisation

- Chronological split by window order; the last `ceil((W+L+H)/S) - 1`
  training windows before the test period are **purged**, so no training
  window's observation or horizon overlaps test data.
- Generalisation is evaluated across groups keyed by **`source_id`** or
  `data_category` (`evaluation.py`). There is no scenario or episode field
  in the schema, so **to evaluate across scenarios, import each scenario
  under its own `source_id`**. For CSE-CIC-IDS2018, for example, one
  `source_id` per capture day.

## 7. Fit of the candidate datasets

| | CSE-CIC-IDS2018 | CTU-13 |
|---|---|---|
| Column names | **Only 1 of 10 processed files matches** (verified by header reads, ADR-088): Tuesday 20-02-2018 has all 12 mapped columns; the other nine lack `Src IP`/`Dst IP` | **Do not match**: Argus `binetflow` uses `StartTime`, `SrcAddr`, `Sport`, `DstAddr`, `Dport`, `TotPkts`, `TotBytes`, `Label` |
| Labels | `Benign` plus attack names: works with the attack rule as is | `Background`, `Normal`, `Botnet` flows. **Needs a reviewed mapping**: under the current rule Background and Normal-prefixed strings would count as attacks, and Background must not become a negative |
| Must verify on acquisition | Time zone of `Timestamp` (unstated by the publisher); that labelled attack rows align with the published schedule | The real label strings, before writing any mapping |
| Other approvals | Download size only (4.05 GB for the one compatible file); plain HTTPS works, no AWS CLI needed | The dataset distributes malware executables |

So only one CSE-CIC-IDS2018 file (Tuesday 20-02-2018) is importable as it
stands - one day, two attack episodes - and CTU-13 needs an importer and a
label mapping first (ADR-072, ADR-088).

## 8. What a real run would and would not establish

It would establish how well the models - the constant, persistence and
rate-threshold baselines, logistic regression, random forest, a temporal
window-stack model and a NumPy LSTM (`forecaster.py`) - anticipate **the dataset's labelled attack flows** 30-90
seconds ahead, on held-out later traffic and across held-out sources.

It would **not** establish: event-level lead time (matching is per window),
performance under alert suppression (none is modelled), behaviour on live
telemetry from this host (which is unlabelled), or anything about real
compromise.

## 9. Procedure once a dataset is approved

1. Set `PRAHARI_RESEARCH_DATABASE_URL` to a dedicated research database.
   Imports are refused without one, and the operational databases are
   never used.
2. `POST /api/v1/research/import/csv` with the policy above. It is a
   **dry run** by default: read the manifest (per-file SHA-256, row
   accounting, rejections), then repeat with the import confirmed.
3. Run the feasibility audit; its provenance check now fails on mixed or
   model-generated labels.
4. Train and evaluate; capture the experiment manifest (git revision,
   configuration hash, target fingerprint, limitations), and replay it.

> **Correction (17 Oct 2026, ADR-088).** An earlier version of section 7
> said CSE-CIC-IDS2018 was "importable as it stands once acquired". Header
> reads showed that holds for **one of ten** processed files. See
> `DATASET_ACQUISITION.md` for the per-file table and the options.

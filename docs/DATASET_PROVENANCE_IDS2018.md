# CSE-CIC-IDS2018 — Acquisition Record and Audit Findings

Blueprint §8 requires recorded provenance, hashes, schema and leakage
controls for any dataset used in evaluation. This is that record for the
first corpus PraHari has acquired.

**The data itself is not in this repository** (`/datasets/` is ignored).
This file is the durable record; the bytes are reproducible from the
source URL and the hashes below.

---

## 1. Acquisition

| Field | Value |
|---|---|
| Dataset | CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity / CSE) |
| Subset | `Processed Traffic Data for ML Algorithms/` — CICFlowMeter-V3 flow CSVs |
| Source URL | `https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/` |
| Access method | Public S3 bucket over plain HTTPS. No account, no credentials, no AWS CLI |
| Licence / terms | **No named licence.** The publisher's page states the dataset may be redistributed, republished and mirrored provided use cites the dataset and links its AWS page |
| Required citation | Sharafaldin, Lashkari and Ghorbani, ICISSP 2018 |
| Terms accepted by | The repository operator, who authorised the download on 21 Oct 2026. Claude did not accept terms on anyone's behalf |
| Acquisition date | 21 Oct 2026 |
| Files acquired | All 10 per-day CSVs; 6.41 GB total |
| Not acquired | `Original Network Traffic and Log data/` — 446.34 GB of PCAPs and host logs. PraHari's research path reads flow CSVs |
| Bucket total | 452.75 GB across 42 objects, listed 21 Oct 2026 |

### SHA-256 per file

```
d96f38e7496aba83475031e6fb8c6fdf1abf6aa1b71325a917798f3c7de93de1  Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
1a4919faa0c49c7af97230b0c2d076eba23ee6dd81103a3801d51ac316355d8b  Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
d0a7f5059d9823b6e9b392b759e306481a3502d190dea7a1b5502ae079ea069b  Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
7287a4d7740a1dddbf330ceb2beb6a4889d33ba63674558a68b5eb50d16711df  Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv
b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf  Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b  Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
da33c927018274f9d49b145baa00e4ce0526c25b3b890b34c489e247b5e24544  Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147  Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
a5f4a1c2689e0aa6566c03a58466de9c407c0be0cbd3cc69306544026611be04  Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
f15e2a12304446058a0186c8ad67de2bd15735a9ba5c70c9a1f4c4242ab06771  Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
```

A SHA-256 proves **byte identity only**. It does not prove authenticity,
publisher provenance, or that the labels are correct.

### Row semantics

Rows are **bidirectional flows** produced by CICFlowMeter-V3, not packets
and not aggregates. `Flow Duration` is **microseconds**; the canonical
schema is seconds, so the import declares the conversion. Labels are
assigned by the publisher from an attack schedule plus addresses, ports
and protocol — they are the **dataset's own labelling rule**, not
independent confirmation of compromise.

---

## 2. Audit findings

Four properties were measured directly from the files. Each one would
have corrupted a result silently if it had gone unnoticed.

### 2.1 The clock is 12-hour with no AM/PM marker

Across every file, the hours present are **01–12 only**. Hour `00` is
absent and so are `13`–`23`. A 24-hour capture cannot look like that.

Confirmed against the publisher's own schedule for 20 Feb 2018:

| Attack run found in the data | Rows | Publisher's stated time |
|---|---|---|
| `01:14` – `01:29` | 797 | DDoS-LOIC-**UDP**, 13:13–13:32 |
| `10:13` – `11:16` | 575,394 | DDoS-LOIC-**HTTP**, 10:12–11:17 |

So `01:14` is really **13:14**. Read naively, the afternoon is placed
**twelve hours before** the morning — scrambling the time axis that every
window, split, purge and lead time depends on.

PraHari's `timestamp_format` policy does not catch this: it disambiguates
`dd/mm` from `mm/dd`, not a 12-hour clock from a 24-hour one.

**Control applied.** Imports are confined to the **08:00–12:59** span,
which reads identically under both interpretations. The afternoon is
excluded rather than repaired by inference. The rule and its reason are
recorded in the derived file's `.provenance.json` beside the parent's
SHA-256.

### 2.2 Nine of ten files are truncated at the spreadsheet row limit

| File | Rows |
|---|---|
| Thuesday-20-02 | 7,948,748 |
| Wednesday-14-02, Thursday-15-02, Friday-16-02, Wednesday-21-02, Thursday-22-02, Friday-23-02, Friday-02-03 | **1,048,575** each |
| Wednesday-28-02 | 613,071 |
| Thursday-01-03 | 331,100 |

1,048,575 is 2²⁰−1 — one short of the Excel worksheet limit. Seven files
sit on it exactly. These are **partial days**, and a per-day rate or
total computed from them understates the real capture. Friday-16-02 is
the most distorted: hours 08, 09, 11 and 12 retain 50, 111, 37 and 53
rows respectively, while hour 01 (i.e. 13:00) holds 908,339.

### 2.3 Addresses are absent from nine of ten files

Only `Thuesday-20-02` carries `Src IP` / `Dst IP` (84 columns). The other
nine begin at `Dst Port, Protocol, Timestamp` (80 columns) and carry no
`Flow ID` either, so the addresses are **not recoverable** from these
CSVs — this was checked, not assumed.

PraHari's importer requires both addresses and two of its twelve features
count distinct addresses, so those nine files are rejected row by row
today.

### 2.4 Both of Tuesday's attacks share one label

The 797 UDP-flood rows and the 575,394 HTTP-flood rows all carry
`DDoS attacks-LOIC-HTTP`. The label cannot distinguish the two episodes,
so they are one labelled class even though the publisher schedules them
as distinct attacks.

---

## 3. What was imported

| Field | Value |
|---|---|
| Derived file | `tue20feb_1000-1030.csv`, SHA-256 `2f7d679bf2b224dbb0f86b63a9b765d0366bbf9e34963cdfb43da15519ff257b` |
| Parent | `Thuesday-20-02-2018_...csv`, SHA-256 `7287a4d7…` |
| Derivation rule | rows whose time-of-day is within [10:00, 10:30] |
| Rows | 607,785 of 7,948,748 — 451,487 Benign, 156,298 attack (25.7 %) |
| Policy | `timestamp_format=day_first`, `duration_unit=microseconds`, `require_bidirectional_counts=true`, `source_timezone=null` |
| Import result | 607,785 read, 607,785 accepted, **0 rejected**, reconciles |
| Quality | 0 duplicates, 22,341 near-duplicate flows counted and kept, no missing/malformed/negative/non-finite values |
| Every record flagged | `timestamp_uncertainty` — the publisher documents no timezone |

Import manifest: `research-data/manifests/import-2f7d679bf2b224dbb0f86b63a9b765d0.json`.

---

## 4. The result, and why it is not a forecasting result

Training ran, and PraHari **refused to call the output interpretable**.

| Split fact | Value |
|---|---|
| Windows generated | 114 (W=60 s, stride 15 s, L=30 s, H=60 s) |
| Train | 48 windows — 2 positive, 46 negative, ending 10:12:45 |
| Purged | 9 windows |
| Test | 57 windows — **57 positive, 0 negative**, starting 10:15:15 |
| Windows with attack already in the observation period | 62 of 114 |

The attack begins at 10:13 and does not end inside the span, so every
window after the split boundary is positive. On a single-class test set:

- `baseline_persistence` and `baseline_threshold` score precision,
  recall and F1 of **1.0000** — by predicting "attack" always;
- logistic regression, random forest, the temporal stack and the LSTM
  score **0.0000** — by predicting "benign" always;
- PR-AUC is undefined for every model.

**Every model is marked `metrics_interpretable: false`.** A system
without that control would have published "F1 1.0000 on real CSE-CIC
data".

The event-level evaluation (ADR-091) refused separately, and for a
different reason:

> All 1 documented event(s) fall outside the evaluated holdout's reach:
> no evaluated window could have warned for any of them. Reporting a
> missed-event rate here would blame the model for windows it was never
> given.

The event starts at 10:13; the holdout starts at 10:15:15. No holdout
window sits in the qualifying interval, so the event is excluded from the
denominator rather than scored as missed.

### Why no span of this day would fix it

20 Feb 2018 contains **one attack onset** in the unambiguous AM span. A
chronological split needs positives on both sides, and the only windows
that forecast an *onset* rather than a continuation are the handful
around 10:13 — the `train_positive: 2` above. Widening the span to
include the attack's end at 11:16 would produce interpretable numbers,
but they would measure "an attack already running will continue", which
the persistence baseline satisfies by construction. That is detection,
not early warning.

**Conclusion: this day cannot support an honest forecasting evaluation.**
That is a property of the data, not a defect in the pipeline, and the
pipeline said so rather than producing a number.

---

## 5. Where a real result is available

Days with several distinct onsets in the unambiguous AM span, measured
from the files:

| Day | AM attack runs | Scheduled attacks |
|---|---|---|
| **Thursday-15-02** | `09:27–09:31`, `09:37–09:40`, `09:49–09:57`, `11:00–11:42` | DoS GoldenEye, DoS Slowloris |
| Wednesday-14-02 | `10:33–12:10` | FTP-BruteForce, SSH-Bruteforce |
| Wednesday-28-02 | `10:50–12:04` | Infiltration |
| Thursday-01-03 | `09:57–10:54` | Infiltration |
| Friday-02-03 | `10:13–12:59` | Bot |

**Thursday-15-02 is the strongest candidate**: four separated onsets in
one morning, ~659,000 rows across hours 08–12, which a chronological
split can divide with positives on both sides.

Every one of these is an 80-column file, so none can be imported until
the address-less schema is supported (§2.3). The day PraHari *can* read
today is the one day that cannot answer the research question.


---

## 6. Thursday 15 Feb 2018 — the first interpretable result (ADR-096)

Once the address-less schema existed (§2.3), the day with several onsets
became importable.

| Field | Value |
|---|---|
| Derived file | `thu15feb_0800-1259.csv` from `Thursday-15-02-2018_...csv`, SHA-256 `fa2947a8…` |
| Derivation rule | rows whose time-of-day is within [08:00, 12:59] — the span where the 12-hour clock is unambiguous |
| Rows | 659,226 of 1,048,575 |
| Labels | Benign 606,728 · DoS-GoldenEye 41,508 · DoS-Slowloris 10,990 |
| Policy | `day_first`, `microseconds`, bidirectional required, **`address_columns=absent_in_source`**, timezone unknown |
| Import | 659,226 read, 659,226 accepted, **0 rejected**, reconciles |
| Feature schema | `prahari.window_features.addressless.v1` (10 features) |
| Near-duplicates | 481,160 (73 %) — counted and kept. Against 22,341 on the addressed day: a direct consequence of dropping addresses |

Attack onsets in the span: **09:27, 09:37, 09:49, 10:02, 11:00**.

### The split decides the answer

| Split | Holdout contains | LSTM PR-AUC | Persistence PR-AUC |
|---|---|---|---|
| 0.6 — test starts 11:08:57 | continuations only | **0.9925** | 0.9562 |
| 0.5 — test starts 10:41:27 | the 11:00 **onset** | **0.3387** | 0.9420 |

At 0.6 the window-level numbers are excellent and the **event-level
evaluation refuses**: all five onsets precede the holdout, so no evaluated
window could have warned for any of them. The 131 positive test windows
are continuations of an attack that started during training.

At 0.5, with one real onset in the holdout:

| Model | PR-AUC | Precision | Recall | F1 |
|---|---|---|---|---|
| `baseline_persistence` | 0.9420 | 0.9649 | 0.9649 | 0.9649 |
| `baseline_constant` | 0.3115 | 0.0000 | 0.0000 | 0.0000 |
| `lstm_forecaster` | **0.3387** | 0.1020 | 0.0292 | 0.0455 |
| `temporal_window_stack` | 0.2259 | 0.0000 | 0.0000 | 0.0000 |
| `random_forest_forecaster` | 0.2112 | 0.0000 | 0.0000 | 0.0000 |
| `logistic_regression` | 0.2435 | 0.0000 | 0.0000 | 0.0000 |

Event-level, LSTM: **1 event in coverage, 0 warned, missed-event rate 1.0**,
2 late warnings during the attack, 7 false alarms (3.08/hour), alarm duty
cycle 9.0 %, no lead time to report. Four events excluded — their onsets
precede the holdout.

The split was moved from 0.6 to 0.5 for event-level **coverage**, not for a
better number; both runs are recorded so the choice is visible, and moving
it made every headline figure worse.

### Conclusion

**On this corpus the learned models do not forecast attack onsets.** The
strong figures at the 0.6 split measure detection of an attack already in
progress, and the trivial persistence rule does that better than any
model. One event in coverage is too few for a robust rate — the report
says so itself — so this is a negative result on one day of one corpus,
not a verdict on the approach.

Manifest: `research-data/experiments/ids2018-thu15feb-onset-split.json`,
dataset fingerprint `40c038396cb19fff…`.

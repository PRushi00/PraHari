# PraHari — Cross-Period Generalization (§10)

Blueprint §10 requires that generalization be evaluated, and
`BLUEPRINT_COVERAGE.md` carried that row as `ABSENT — one corpus only`.
This is the measurement that closes it, and the result is **negative and
quantified**.

**Reproduce:** import both derived day-slices under distinct `source_id`s,
then `POST /forecast/generalization` with `group_by=source_id`.

---

## 1. What was and was not possible

CIC-IDS2017 — the intended second *dataset* — is behind a registration
form requiring a person's name, email, organisation, job title and
country. That is the operator's to submit, and no public bucket exists
(verified: the IDS2018 bucket answers 200; the obvious 2017 bucket names
return 404). CTU-13 was ruled out separately: it distributes each
scenario's malware executable, states no licence, and needs a label
mapping that does not exist (ADR-072).

So this is **cross-period**, not cross-dataset: two different days of
CSE-CIC-IDS2018, evaluated leave-one-day-out. It answers "does what the
model learned on one day apply to a day it never saw", which is the
question §10 cares about, and it does **not** answer "does it apply to
another capture environment, another flow exporter, another network".
That remains open.

## 2. A structural constraint of the dataset, stated up front

IDS2018 runs **one attack family per day**, in scheduled blocks. So any
cross-day test on this corpus is **also cross-attack-family**. The two
variables cannot be separated with this data, and no design here
pretends otherwise.

A same-family pair was looked for and rejected on the evidence: Friday
16 Feb carries DoS Hulk and SlowHTTPTest — the same family as Thursday's
GoldenEye and Slowloris — but inside the span where the source's
12-hour clock is unambiguous it holds **139,890 attack rows against 345
benign**, 99.75 % positive. A test set that is almost entirely positive
is as uninformative as one that is entirely negative.

That is worth recording as a finding in its own right: the 12-hour clock
defect (ADR-095) does not merely lose rows, it **biases which rows
survive**, because the attacks were run in scheduled blocks and the
surviving span can coincide with one.

## 3. The two days

Both slices use the identical rule — rows whose time-of-day falls in
[08:00, 12:59], the only span that reads the same under both readings of
the 12-hour clock. Applying the same rule to both days is what makes the
comparison fair.

| | Thursday 15 Feb | Wednesday 14 Feb |
|---|---|---|
| Slice | `thu15feb_0800-1259.csv` | `wed14feb_0800-1259.csv` |
| Parent SHA-256 | `fa2947a8…` | `acff8bc6…` |
| Slice SHA-256 | (recorded in its provenance JSON) | `45fe17a3…` |
| Rows kept / in parent | 659,226 / 1,048,575 | 670,184 / 1,048,575 |
| Attack family | DoS GoldenEye, Slowloris | FTP-BruteForce |
| Accepted on import | **659,226**, 0 rejected | **670,184**, 0 rejected |
| Positives | 52,498 (**8.0 %**) | 193,360 (**28.9 %**) |
| Feature schema | `addressless.v1` | `addressless.v1` |

Both reconcile. Embedded repeated-header rows — a known IDS2018 defect
that would otherwise arrive as records labelled `Label` — are counted
and skipped by the slicer; Wednesday's window contained none.

## 4. The result

Leave-one-day-out. The held-out day contributes nothing to training. The
within-day score is computed by the ordinary chronological protocol on
that day alone, so the **gap** is read directly rather than inferred.

| Train → Test | Model | Test inst. / pos. | Within-day PR-AUC | Cross-day PR-AUC | Transfer gap |
|---|---|---|---|---|---|
| Wed 14 → Thu 15 | random forest | 1,097 / 243 | **1.0000** | **0.3852** | **0.6148** |
| Thu 15 → Wed 14 | NumPy LSTM | 1,077 / 392 | 0.9774 | **0.6979** | **0.2795** |

Cross-day precision and recall: 0.5904 / 0.2016 and 0.7564 / 0.6735.

**Mean transfer gap: 0.4472.** Two groups evaluated, none refused.

## 5. Reading it honestly

**The within-day 1.0000 is a red flag, not an achievement.** A PR-AUC of
exactly 1.0 on 1,097 instances is the "suspiciously perfect metrics" row
of `TROUBLESHOOTING.md`, and it has the same cause this project has
twice diagnosed: within a day the model is largely distinguishing
*ongoing* attack activity, which is continuation rather than forecasting
(ADR-096). So the transfer gap is measured against an **inflated**
baseline.

That strengthens the finding rather than weakening it. Even measured
against a within-day score inflated by continuation, performance on an
unseen day **collapses** — to 0.3852 in one direction, 0.6979 in the
other.

**The asymmetry is real and unexplained.** DoS → BruteForce transfers
better (0.6979) than BruteForce → DoS (0.3852). With one pair of days
there is no basis to say whether that is about the attack families, the
very different positive rates (8.0 % against 28.9 %), or the particular
models each direction selected. It is reported, not explained.

**The test sets are small.** 659,226 and 670,184 events reduce to 1,097
and 1,077 windowed instances after purging, with 243 and 392 positives.
Enough for a direction, not enough for a tight interval.

## 6. What this establishes, and what it does not

**Establishes:** on this corpus, a model fitted on one day does not
transfer to another day, with a measured mean PR-AUC gap of 0.4472. The
§10 generalization row is now a measurement rather than an absence.

**Does not establish:**

- anything about a different **dataset**, exporter or network — this is
  two days of one capture;
- which of *day* or *attack family* drives the drop, since IDS2018
  confounds them by design;
- a tight estimate of the gap, from one day-pair and ~1,100 instances
  per direction;
- any contradiction of the earlier finding. The project's headline
  result stands: on CSE-CIC-IDS2018 the learned models do not forecast
  attack onsets, and this adds that they do not transfer across days
  either.

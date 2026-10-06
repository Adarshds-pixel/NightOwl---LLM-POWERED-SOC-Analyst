# NightOwl — Unsupervised ML Integration

## Ledoit-Wolf Mahalanobis anomaly detection: architecture, evaluation, and limits

> **Purpose:** This document defines the unsupervised anomaly-detection layer that
> supplements NightOwl's Sigma rules. It replaces earlier experimental concepts
> (Isolation Forest, TF-IDF) and documents the evaluation methodology, the measured
> results, and what this layer can and cannot be relied on to do.
>
> **Revision note (2026-10-05):** the metrics in the previous version of this
> document (Accuracy 97.80%, Precision 83.87%, Recall 61.90%, F1 71.23%) were
> measured on the training set and are withdrawn. §4 explains what was wrong with
> them and §5 reports host-held-out replacements. The honest numbers are
> substantially worse. See `docs/DOCUMENTATION.md` §9 for the project's honesty
> policy, which this correction applies.

---

# 1. Executive summary

NightOwl converts Windows Sysmon/EVTX telemetry into prioritized incidents through
deterministic Sigma-style rules, multi-event sequence correlation, and RAG/LLM
incident explanation.

The ML layer adds unsupervised anomaly detection using **Ledoit-Wolf shrunk
covariance + Mahalanobis distance**. It learns the covariance structure of normal
Windows behaviour strictly from benign telemetry, evaluates 10-minute host
behaviour windows, and flags windows whose distance exceeds a percentile of the
benign baseline.

**What the measurements support:** on a host the baseline actually covers, the
layer is meaningfully better than chance at separating attack windows from normal
ones (PR-AUC 0.77 against a 0.25 base rate on `Server002`), and at a strict
threshold it is reasonably precise (85% precision at the 99.5th percentile on that
host). Its **recall is low — about 13%**. It finds roughly one attack window in
eight.

**What the measurements do not support:** any claim that this layer is a detector
in its own right. It is supplementary evidence of unusual host behaviour. Known
threats and single-event Living-off-the-Land executions are caught by the Sigma
rules and the sequence engine, which is where NightOwl's actual 50/61 (82.0%)
detection rate comes from.

---

# 2. Architecture

## Algorithm

**Ledoit-Wolf Mahalanobis distance** over `log1p`-transformed feature vectors.

* **Why not Isolation Forest?** It suffered from the curse of dimensionality across
  50+ dense volumetric features, producing unstable anomaly scoring and a high
  false-positive rate.
* **Why not TF-IDF over command lines?** Standard Windows background noise (Temp
  paths, GUIDs) introduces extreme natural variance that swamps malicious strings.
* **Why Ledoit-Wolf specifically?** Shrinkage keeps the covariance matrix
  invertible across correlated, highly skewed behavioural features without
  hand-tuning a regularization term.

## Feature extraction

`backend/app/ml/features.py` produces **70 features** per (host, 10-minute window):

* **53 volumetric** — event-ID counts (Sysmon 1/3/11, Security 4624/4688/…),
  per-minute rates, unique process/destination/user counts, command-line
  statistics, ratios.
* **8 basic heuristics** — service creation, account/group change, log cleared,
  LSASS access, LOLBin usage, suspicious PowerShell, remote named pipe, admin
  share access.
* **9 advanced content-aware heuristics** — `exploit_tool_regex_match`,
  `uac_bypass_registry_count`, `winrm_spawned_recon_count`,
  `suspicious_service_imagepath_count`, `accessibility_hijack_count`,
  `advanced_lolbin_count`, `db_failed_logon_count`, `domain_enumeration_count`,
  `account_tampering_count`.

This module lives under `app/`, not `scripts/`, because the live ingest path
imports it. It previously lived in `backend/scripts/`, which neither
`.dockerignore` nor the Dockerfile's `COPY` list includes — so in every container
build the import raised `ModuleNotFoundError`, a bare `except Exception` swallowed
it, and **the ML layer silently never ran in Docker at all.**

## Only 28 of the 70 features are actually used

`NightOwlAnomalyDetector.train()` drops any feature the benign corpus cannot
support — constant, or non-zero in under 1% of windows — and records the survivors
as the model's schema. On the current corpus that leaves **28 features**; 42 are
dropped.

This is not tuning. Mahalanobis distance is scale-free, so a feature the baseline
never exercises gets only the shrinkage floor as its variance (≈4e-4 here), and its
first ordinary value in production reads as an enormous deviation. Measured against
the previous 70-feature model:

| scenario | old 70-feature model | current 28-feature model |
|---|---|---|
| median benign window | 22.5 — Low | 20.2 — Low |
| **normal host, 120 network connections** | **77,940 — High** | **193 — Low** |
| **benign admin, 8 PowerShell script blocks** | **11,936 — High** | **64 — Low** |
| noisy enumeration burst (400 processes) | 12,514 — High | 9,084 — High |

The benign corpus contains almost no Sysmon EID 3: `unique_destination_count` is 0
in all 1829 windows and `network_event_count` is non-zero in 6. The 70-feature
model would therefore have fired `High` on essentially every 10-minute window of
any host that browses the web. The dropped features are listed by
`scripts/train_ml_model.py` on every run.

**Cost of the cull:** 7 of the 9 advanced heuristics are among the dropped
features, and they were the single strongest signal in the old model (a single
firing added ~1181 to the distance, 2.7× the threshold). Recall falls as a result.
That is the correct trade: those features only "worked" because the baseline never
saw them fire, which is the same property that would make them fire on benign
production hosts. Catching those specific executions is the Sigma rules' job.

## Scoring

Thresholds are the 99.5th (suspicious → Medium) and 99.9th (→ High) percentiles of
the **training** distances. They describe the baseline's own spread. They are not a
false-positive rate, and §4 is about what happens when they are mistaken for one.

---

# 3. Dataset

| | windows | source |
|---|---|---|
| Benign | 1829 | `NightOwl-Benign-Dataset/` — 31 EVTX files, 2 hosts: `LAPTOP-5GVGMJ14` (952), `Server002` (877) |
| Attack | 87 | `real_world_fixtures/detected/` (50 files) + `undetected/` (11 files) |

## The `bits_openvpn.evtx` exclusion

One attack-folder capture contains 1,537 `Microsoft-Windows-Bits-Client` events
from routine Windows Update / Google Update / OneDrive polling, with zero malicious
events and no OpenVPN traces. The dataset pipeline labels every window in an attack
capture `is_attack = 1`, so its 190 benign windows counted as false negatives. The
model scored them correctly as benign; the label was wrong.

Those 190 windows are excluded. This is a ground-truth correction, not a
convenience — but it is an exclusion that improves the reported metric, so it is
named explicitly as `MISLABELED_CAPTURES` in `scripts/eval_ml_model.py` rather than
applied silently.

## Baseline coverage is the limiting factor

Two hosts is not a baseline. It is why 42 features have no support, why the two
hosts disagree so sharply in §5, and why no number in this document should be
expected to hold on a third machine.

---

# 4. What was wrong with the previous metrics

The previous §4 reported Accuracy 97.80%, Precision 83.87%, Recall 61.90%, F1
71.23%, TN 1819 / FP 10.

**The benign half of that evaluation was the training set.** `scratch_prod_eval.py`
loaded its benign windows from `scripts/ml_features.csv` — the same file
`train_ml_model.py` fits on. TN + FP = 1829 = that file's row count exactly.

Since the threshold is the 99.5th percentile *of the training distances*, "10
benign windows flagged out of 1829" (0.547%) is arithmetic, not a measurement. Any
model trained this way produces that number. Refitting with 5-fold cross-validation
gives an out-of-sample rate of **0.875% ± 0.27** on the same corpus, and the
host-held-out protocols in §5 give 2.1–3.8%.

Two further problems with those figures:

* **Accuracy was meaningless at that class ratio.** 1829 benign vs 87 attack means
  a classifier that never fires scores **95.6%**. The reported 97.80% was 2.2
  points above doing nothing.
* **They no longer reproduced.** Re-running the same script today gives 87 attack
  windows, TP 60 / FN 27, recall 68.97%, F1 76.43% — not 84 / 52 / 32 / 61.90% /
  71.23%. This document was written 2026-09-28 18:18; `extract_ml_features.py` was
  last edited at 18:49. The published numbers described a pre-final extractor, and
  the "32 remaining false negatives" breakdown described a run that no longer
  existed.

Only **recall** in the old table was measured on genuinely unseen data.

### The previous explanation for the false negatives was also wrong

The old §5B attributed the stealth misses to covariance mathematics: "appending a
Boolean heuristic does not guarantee an anomaly spike if the benign dataset has
non-zero variance for that feature."

The benign variance for those features was exactly **zero**, which made them
extremely powerful rather than weak — a single firing moved the distance by ~1181
against a 439 threshold. The misses were windows where the heuristic **did not
fire**: extraction-logic gaps, not a mathematical ceiling. For example,
`Discovery_Remote_System_NamedPipes_Sysmon_18` uses the pipes `\wkssvc` and
`\browser`, while the extractor matched only `lsarpc|samr|svcctl|srvsvc`.

---

# 5. Measured results

Produced by `backend/scripts/eval_ml_model.py`. Both protocols refit the model and
re-derive the threshold inside each fold. Benign windows are never split randomly —
consecutive 10-minute windows from one host are near-duplicates, so a random split
leaks.

## Protocol A — within-host temporal split (the deployment condition)

Fit on each host's first 70% of windows by time; score its last 30% plus all 87
attack windows. This is what deployment looks like: the baseline covers the host
being monitored, and the question is whether its later windows read as normal.

| threshold | Precision | Recall | F1 | benign FP rate |
|---|---|---|---|---|
| 99.0th pct | 52.83% | 16.09% | 24.67% | 4.55% |
| **99.5th pct (shipped)** | **52.27%** | **13.22%** | **21.10%** | **3.82%** |
| 99.9th pct | 59.46% | 12.64% | 20.85% | 2.73% |

**PR-AUC 0.4931** against a 0.2403 random baseline — a 2.05× lift.

The two hosts differ sharply, and the average hides it:

| host | features fitted | PR-AUC (random) | Precision @99.5 | Recall @99.5 |
|---|---|---|---|---|
| `Server002` | 28 / 70 | **0.7701** (0.2479) | 84.62% | 12.64% |
| `LAPTOP-5GVGMJ14` | 7 / 70 | 0.3325 (0.2332) | 38.71% | 13.79% |

On the server the layer works: 3.1× lift over chance, 85% precision, 2 false
positives in 264 held-out benign windows. On the laptop it barely beats chance —
only 7 features survived the support test, because a single workstation generates
too narrow a behavioural range to model.

## Protocol B — host-held-out (transfer to an unseen machine)

Fit on one host, score the other entirely. Pessimistic by design: in deployment the
baseline would include the monitored host. Reported because it bounds how far a
single-host baseline transfers.

| threshold | Precision | Recall | F1 | benign FP rate |
|---|---|---|---|---|
| 99.0th pct | 5.99% | 20.11% | 9.23% | 30.02% |
| **99.5th pct (shipped)** | **29.63%** | **9.20%** | **14.04%** | **2.08%** |
| 99.9th pct | 42.42% | 8.05% | 13.53% | 1.04% |

**PR-AUC 0.1464** against a 0.0869 random baseline — a 1.68× lift.

A baseline from one machine does not describe a different kind of machine. At the
99.0th percentile, a model fitted on the laptop flags 531 of Server002's 877
windows.

## Accuracy

Deliberately not headlined. At these class ratios the majority-class baseline is
75–96% depending on the fold, and accuracy tracks it almost exactly. The evaluation
script prints it only with that baseline beside it.

## Summary

| | previous claim | measured (Protocol A, 99.5th) |
|---|---|---|
| Precision | 83.87% | 52.27% |
| Recall | 61.90% | **13.22%** |
| F1 | 71.23% | 21.10% |
| Benign FP rate | 0.55% | 3.82% |
| Accuracy | 97.80% | not quoted without its baseline |

---

# 6. Limits and conclusion

> **NightOwl is a hybrid Windows SOC platform. The ML layer is supplementary
> evidence, not a detector.**

What it provides: a signal that a 10-minute host window deviates from the host's
established behavioural baseline — noisy enumeration, volumetric spikes, unusual
process mix. At the shipped threshold it is right about half the time it fires, and
it fires for roughly one attack window in eight.

What it does not provide, and must not be described as providing:

* **Technique attribution.** An anomaly score maps to no ATT&CK technique. ML
  alerts carry `technique_id = None` deliberately (`app/ml/rule.py`); inventing one
  would be exactly the fabricated confidence `docs/DOCUMENTATION.md` §9 forbids.
* **Coverage of stealth execution.** Single-event Living-off-the-Land activity
  generates too little volume to shift a Mahalanobis distance. This is the Sigma
  rules' and the sequence engine's job, and they do it: 50/61 (82.0%) with 0 false
  positives.
* **Any guarantee on an unmodelled host.** See Protocol B.

## Known work

1. **Extend the benign corpus.** The binding constraint is two hosts and no network
   telemetry. Captures containing Sysmon EID 3 and PowerShell 4104 would restore
   the ~42 dropped features, most of the recall, and the advanced heuristics —
   without the false-positive cliff that made them unusable before.
2. **Per-host baselines.** Protocol B shows a shared model transfers poorly. One
   model per monitored host, fitted on that host's own history, matches how the
   layer actually performs best (`Server002`, PR-AUC 0.77).
3. **Close the extraction gaps from §4.** Extend the named-pipe list (`wkssvc`,
   `browser`, `atsvc`, `winreg`, `spoolss`) and audit the other advanced heuristics
   against `scripts/32_fns_dump.txt`. These are cheap recall wins once the corpus
   supports the features again.

## Reproducing these numbers

```bash
cd backend
./venv/Scripts/python.exe scripts/extract_ml_features.py   # rebuild the benign matrix
./venv/Scripts/python.exe scripts/train_ml_model.py        # fit + report dropped features
./venv/Scripts/python.exe scripts/eval_ml_model.py         # both protocols
```

Add `--rebuild` to `eval_ml_model.py` to re-parse the attack EVTX corpus rather
than using the cached matrix.

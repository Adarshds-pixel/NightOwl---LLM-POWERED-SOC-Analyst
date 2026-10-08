# NightOwl ML anomaly layer

**Status: experimental, advisory by default.** The layer is wired end to end and its records carry their own evidence, but measured on the data available today it is not accurate enough to raise alerts. It therefore never opens or changes an incident and is never counted as a detection. Everything below is reproducible with `backend/scripts/train_ml_model.py` and `backend/scripts/eval_ml_model.py`.

## What it does

The unit is a **window**: all events of one log family (Security, Sysmon, PowerShell, System or Application) from one host within one 10-minute bucket. That is exactly what one uploaded EVTX file produces, since one file is one channel, so the model is trained on the same shape of data it scores.

Per family, a window is described by:
- its **composition**: counts of the family's 15 most common event ids in the benign baseline (the *vocabulary*, stored with the model) plus an "other" bucket;
- **size and diversity**: total events and distinct event ids;
- **behaviour counts** for that family:

| Family | Behaviour counts |
|---|---|
| Security | failed logons, distinct logon accounts and sources, network/RDP logons, explicit-credential logons, account and group changes, distinct new processes |
| Sysmon | process creations, distinct processes, distinct parent→child pairs, network connections, distinct destinations and ports, distinct processes accessed |
| PowerShell | script block count and size |
| System | service installs and state changes |

Every feature is scoped to its family. Event ids are never compared across channels: Sysmon 1 is a process creation, System 1 is a clock change.

Each family gets a Ledoit-Wolf covariance model over `log1p` features. A window is scored by its Mahalanobis distance from the benign baseline:
- **medium** beyond the 99.5th percentile of training distances;
- **high** beyond the 99.9th percentile.

Windows with fewer than 10 events are never scored. A handful of events is not "behaviour", and single-event attacks are the rules' job.

Each flagged window is stored as an alert record (`rule_id = ml-anomaly-detector`) whose `details` hold:
- the family, distance and thresholds;
- the window bounds and event count;
- the **top contributing features**, each with its value, the baseline median and its share of the distance (the distance is zᵀPz, so feature *i* contributes z_i(Pz)_i);
- any event ids never seen in the baseline.

The console shows this under Alerts → "ML anomalies (experimental)" and in incident evidence, always labelled as not a detection.

## Modes (`ML_MODE` in `.env`)

| Mode | Behaviour |
|---|---|
| `advisory` (default) | Record anomalies with evidence. Link them to an incident that already covers the host and time. Never open or change an incident. |
| `alert` | As advisory, but may open a new incident (still with no ATT&CK technique). |
| `off` | No scoring. |

In every mode anomalies are excluded from `rule_matches`, `alerts_created`, "alerting events" and every detection count, and are never chosen as the alert an incident explanation is built around.

## Training data

`sample_logs/real_world_fixtures/NightOwl-Benign-Dataset/`: 31 EVTX files from **two machines** (`LAPTOP-5GVGMJ14`, `SERVER002`). Overlapping exports are de-duplicated by (host, channel, EventRecordID).

| Family | Benign windows | Features fitted (dropped) | Thresholds medium / high |
|---|---:|---:|---:|
| Security | 531 | 17 (8) | 143.7 / 199.7 |
| Sysmon | 762 | 7 (6) | 55.9 / 61.3 |
| System | 227 | 20 (0) | 50.6 / 61.2 |
| Application | 179 | 17 (1) | 55.9 / 98.8 |
| PowerShell | 24 | not modelled (< 30 windows) | -- |

A feature is dropped when it is non-zero in under 2% of benign windows: with no baseline variance, its first ordinary value would read as an enormous deviation. The bundle records the scikit-learn version it was trained with, and the loader refuses it under any other version.

## Held-out evaluation (`scripts/ml_eval_results.json`)

**A. Within-host temporal split (the deployment condition).** Each host's windows are split chronologically: train on the first 70%, test on the last 30%.

| Family | Held-out benign windows | Flagged | ≈ false alerts per host-day |
|---|---:|---:|---:|
| Security | 161 | 5 | 4.5 |
| System | 69 | 2 | 4.2 |
| Application | 55 | 1 | 2.6 |
| Sysmon | 229 | 2 | 1.3 |

**B. Leave one host out (transfer to an unseen machine).** This fails badly. For example:
- Security windows from the laptop, scored by a server-only model: 44% flagged.
- System windows: 42–70% flagged.

**C. Unseen benign captures.** Data never used in training:
- a separate benign laptop export: 27 of 314 windows flagged (8.6%);
- the synthetic noise files: 5 of 5 flagged, because their volume is unlike anything in the baseline.

**D. Attack captures.** Only 26 of 87 attack windows are large enough to score; 24 of those were flagged. That figure is **not** evidence of skill. Protocols B and C show the model flags almost any unfamiliar machine, and every attack capture comes from a machine outside the baseline.

**Conclusion.** With two baseline hosts the layer cannot separate "attack" from "unfamiliar machine", and on a familiar machine it still produces 1–4.5 false windows per day. That is why the default mode is advisory.

## Checking the ML layer visually

Everything the model does is visible in the console:

1. **Settings -> About -> ML model (experimental)** shows the mode, the training date, how many 10-minute windows and machines each log family was trained on, the two thresholds, and the false-alarm rate measured on held-out benign data (`GET /ml/model`).
2. **On every upload**, the Telemetry profile adds an "ML check (experimental)" line when windows looked unusual, with a link to the ML view.
3. **Alerts -> ML anomalies (experimental)** lists every record; the eye icon opens its evidence: the log family, the distance against both thresholds, the window and its event count, the features that drove the score (this window against the baseline median, with each feature's share of the distance) and any event types never seen in training.
4. **A visual test you can repeat:**
   - Upload a benign file such as `NightOwl-Benign-Dataset/system_baseline.evtx`: expect no or very few ML records.
   - Upload an attack capture the model flags, such as `detected/de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx`, and open the record. Read the "What drove the score" table before trusting the flag: on the sample captures it is mostly driven by what is *missing* (for example no process-exit events where the baseline has about 16 per window), because these captures are short excerpts, not a whole machine's activity. That is the layer's honest limitation today: it detects "this window looks different from the machines I was trained on", not "this is an attack".
   - Upload one of your own benign machines' logs: a record there is a false alarm, and it is exactly what the retraining step (below) is meant to reduce.

## How to make it better

The binding constraint is data, not the algorithm:
1. Collect benign logs with `backend/scripts/collect_benign_logs.ps1`:
   - at least 5 more machines, a mix of workstations and servers;
   - 3+ normal working days each;
   - Sysmon network (event 3) and image-load (event 7) events enabled.
2. Retrain with `./venv/Scripts/python scripts/train_ml_model.py --extra-dir <folder>`.
3. Re-run `scripts/eval_ml_model.py`.
4. Switch `ML_MODE=alert` only if protocol A stays at or below about 1 false window per host-day and protocol C improves.

## History

Two earlier versions were withdrawn.
- **First version: one 70-feature model over windows merging every channel of a host.** It reported 97.8% accuracy and 83.9% precision. Those numbers were measured on its own training data, at a class ratio where a model that never fires already scores 95.6%. Under honest evaluation it reached about 52% precision at 13% recall.
- **Its scoring shape.** Production then scored single-channel uploads, so one ordinary logon scored as a Medium anomaly, while a security-log clear, Mimikatz command lines and encoded PowerShell scored as normal.
- **Its feature set.** Every attack-specific heuristic feature had already been dropped for lack of benign support.

The current design addresses each of these; it does not yet fix the data.

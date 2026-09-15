# NightOwl — Unsupervised ML Integration
## Isolation Forest Workflow, Architecture, and Implementation Concept

> **Purpose:** This document defines the proposed machine-learning enhancement for the NightOwl project. It is based on the existing NightOwl project documentation and the agreed approach of adding **unsupervised Isolation Forest anomaly detection** without replacing the existing Sigma/rule-based detection or RAG/LLM explanation layers.

---

# 1. Executive Summary

NightOwl currently converts Windows Sysmon/EVTX telemetry into prioritized incidents through:

1. EVTX ingestion and normalization
2. Sigma-style rule detection
3. Multi-event sequence correlation
4. Incident grouping and severity scoring
5. MITRE ATT&CK mapping
6. RAG retrieval
7. LLM-based explanation and self-critique
8. SOC web-console presentation

The existing detection layer is **rule-based**, not machine learning.

The proposed ML enhancement adds an **unsupervised anomaly-detection layer using Isolation Forest**.

The ML layer will learn the patterns of normal Windows behavior from primarily benign telemetry and identify behavior windows that are unusual. It will produce an anomaly score and an ML anomaly signal. This signal will be correlated with existing Sigma and sequence alerts.

The recommended architecture is therefore:

**Known malicious behavior → Sigma rules**

**Known multi-event behavior → Sequence engine**

**Unusual/previously unseen behavior → Isolation Forest**

**Explain and investigate evidence → MITRE ATT&CK + RAG + LLM**

---

# 2. Current NightOwl Architecture

The existing NightOwl pipeline is:

```text
                    EVTX UPLOAD
                         |
                         v
                  +--------------+
                  |  INGESTION   |
                  | EVTX Reader  |
                  | Normalizer   |
                  +------+-------+
                         |
                         v
                 NORMALIZED EVENTS
                         |
                         v
                  +--------------+
                  |   DETECTION  |
                  |              |
                  | 45 Sigma     |
                  | rules        |
                  |      +       |
                  | 3 sequence   |
                  | correlations|
                  +------+-------+
                         |
                         v
                      ALERTS
                         |
                         v
                  +--------------+
                  | CORRELATION  |
                  | Same host     |
                  | 1-hour window |
                  +------+-------+
                         |
                         v
                     INCIDENT
                         |
                         v
                  +--------------+
                  |  MITRE + RAG |
                  |     + LLM    |
                  +------+-------+
                         |
                         v
                  SOC WEB CONSOLE
```

The project documentation states that NightOwl turns raw Windows Sysmon/EVTX telemetry into prioritized, explained incidents. Its detection layer uses 45 Sigma-style YAML rules and three multi-event sequence patterns, followed by incident correlation and an AI/RAG explanation layer.

---

# 3. Important Distinction: AI vs ML

NightOwl already contains AI functionality, but it does not currently contain a machine-learning anomaly detector.

| Component | Current Status | Type |
|---|---|---|
| EVTX ingestion | Implemented | Data processing |
| Event normalization | Implemented | Data processing |
| 45 Sigma-style rules | Implemented | Rule-based detection |
| 3 sequence correlations | Implemented | Deterministic correlation |
| MITRE ATT&CK mapping | Implemented | Knowledge/enrichment |
| ChromaDB RAG | Implemented | Retrieval/AI |
| LLM explanation | Implemented | Generative AI |
| Isolation Forest | **Proposed** | **Unsupervised ML** |
| Supervised classifier | Not proposed initially | Supervised ML |

The proposed ML work therefore **adds** machine learning; it does not replace the current detection architecture.

---

# 4. Recommended ML Approach

## Algorithm

**Isolation Forest**

## Learning type

**Unsupervised Learning**

## ML task

**Behavioral anomaly detection**

## Main objective

Identify Windows behavior that is significantly different from learned normal behavior.

The ML system should answer:

> "How unusual is this behavior compared with the normal Windows behavior seen by the model?"

It should not automatically answer:

> "Is this definitely malware?"

An anomaly is a signal for investigation, not proof of maliciousness.

---

# 5. Why Isolation Forest?

Isolation Forest is a strong starting point for NightOwl because:

- It is designed for anomaly/outlier detection.
- It works well with numerical/tabular feature vectors.
- It does not require malicious/benign labels for the initial training process.
- It is relatively lightweight compared with deep-learning alternatives.
- It is easier to integrate into the existing Python backend.
- It is easier to explain and demonstrate in an academic project.
- It can complement deterministic Sigma rules rather than replacing them.

The recommended implementation should start with **one Isolation Forest model** rather than multiple ML models.

Possible future comparison algorithms include One-Class SVM, Local Outlier Factor, DBSCAN, or an Autoencoder, but they should not be added until the first Isolation Forest implementation is working and evaluated.

---

# 6. Final Hybrid Architecture

```text
                         +----------------+
                         |    EVTX FILE   |
                         +-------+--------+
                                 |
                                 v
                        +------------------+
                        | EVTX INGESTION   |
                        | Parse + Read     |
                        +--------+---------+
                                 |
                                 v
                        +------------------+
                        | EVENT NORMALIZER |
                        +--------+---------+
                                 |
                                 v
                        +------------------+
                        | NORMALIZED       |
                        | EVENTS           |
                        +--------+---------+
                                 |
                    +------------+------------+
                    |                         |
                    v                         v
          +-------------------+     +-------------------+
          | SIGMA RULE ENGINE |     | FEATURE ENGINE    |
          | Existing          |     | New ML component  |
          | 45 rules          |     |                   |
          | + 3 sequences     |     | Behavioral        |
          +---------+---------+     | features          |
                    |               +---------+---------+
                    |                         |
                    |                         v
                    |               +-------------------+
                    |               | ISOLATION FOREST  |
                    |               | UNSUPERVISED ML   |
                    |               +---------+---------+
                    |                         |
                    |                         v
                    |                  ANOMALY SCORE
                    |                         |
                    +------------+------------+
                                 |
                                 v
                       +---------------------+
                       | ALERT CORRELATION   |
                       | Sigma + ML +        |
                       | sequence signals   |
                       +----------+----------+
                                  |
                                  v
                           +-------------+
                           |  INCIDENT   |
                           +------+------+
                                  |
                    +-------------+-------------+
                    |                           |
                    v                           v
             +-------------+             +-------------+
             | MITRE ATT&CK|             | RAG         |
             | Enrichment  |             | Retrieval   |
             +------+------+             +------+------+ 
                    |                           |
                    +-------------+-------------+
                                  |
                                  v
                           +-------------+
                           |    LLM      |
                           | Explanation |
                           +------+------+
                                  |
                                  v
                           +-------------+
                           | SOC CONSOLE |
                           +-------------+
```

---

# 7. Complete End-to-End Workflow

## Step 1 — EVTX Upload

The analyst uploads a Windows `.evtx` file.

```text
User
 |
 v
NightOwl UI
 |
 v
POST /ingest
 |
 v
EVTX file
```

The file is processed through the existing ingestion pipeline.

---

## Step 2 — EVTX Parsing

The EVTX reader extracts Windows event records.

Conceptually:

```text
EVTX
 |
 +-- Event 1
 +-- Event 2
 +-- Event 3
 +-- ...
 +-- Event N
```

The raw event information is preserved.

---

## Step 3 — Event Normalization

Each raw event is converted into NightOwl's normalized event representation.

Important fields include:

```text
timestamp
host
event_id
process
parent_process
command_line
user
event_data
raw_json
```

This gives both the existing rule engine and the ML feature extractor a consistent source.

---

# 8. Two Detection Paths

After normalization, the events are processed through two paths:

```text
                    NORMALIZED EVENTS
                           |
             +-------------+-------------+
             |                           |
             v                           v
       EXISTING PATH                NEW ML PATH
             |                           |
             v                           v
       Sigma Rules                Feature Engineering
             |                           |
             v                           v
       Known Threats              Isolation Forest
                                         |
                                         v
                                  Unusual Behavior
```

---

# 9. Existing Sigma Detection Path

NightOwl currently has 45 Sigma-style YAML rules.

The existing engine checks events against the rules.

Example:

```text
Event:
Process = powershell.exe
CommandLine = powershell -enc ...

             |
             v

Sigma Rule Match

             |
             v

Alert
```

The existing system also has three multi-event sequence correlations:

1. Process Herpaderping
2. SMB share-enumeration probe
3. Kerberos password spray

These remain in the system.

The ML implementation should not remove or rewrite these mechanisms.

---

# 10. ML Feature Engineering

This is the most important stage of the new ML pipeline.

Isolation Forest should not receive raw EVTX XML directly.

Instead:

```text
Normalized Events
       |
       v
Group by Host
       |
       v
Create Behavior Window
       |
       v
Extract Features
       |
       v
Feature Vector
       |
       v
Isolation Forest
```

---

# 11. Recommended Behavior Window

Start with a **5–10 minute host-level behavior window**.

Example:

```text
HOST-01

10:00:00 ─────────────── 10:10:00

Events:
  ProcessCreate
  ProcessCreate
  NetworkConnect
  PowerShell
  FileCreate
  ProcessCreate
  ...
```

These events are aggregated into one behavioral feature vector.

Why?

A single event is often insufficient to determine whether behavior is suspicious.

For example:

```text
powershell.exe
```

may be normal.

But:

```text
Word
  |
  +--> PowerShell
          |
          +--> Encoded command
                  |
                  +--> Network connection
                          |
                          +--> certutil
```

is much more interesting from a behavioral perspective.

---

# 12. Feature Categories

## 12.1 Process Features

Examples:

```text
process_count
unique_process_count
rare_process_count
parent_child_relationship_count
parent_child_anomaly_count
```

These describe process execution behavior.

---

## 12.2 PowerShell Features

Examples:

```text
powershell_count
encoded_command_count
script_block_count
suspicious_powershell_pattern_count
```

These describe PowerShell activity within the window.

---

## 12.3 Network Features

Examples:

```text
network_event_count
unique_destination_count
external_destination_count
unique_destination_port_count
```

These describe network behavior.

---

## 12.4 Command-Line Features

Examples:

```text
average_command_length
maximum_command_length
argument_count
suspicious_argument_count
encoded_command_indicator
```

These describe command-line characteristics.

---

## 12.5 User Features

Examples:

```text
unique_user_count
processes_per_user
rare_user_process_combination
```

These describe account/process relationships.

---

## 12.6 Temporal Features

Examples:

```text
events_per_minute
processes_per_minute
network_events_per_minute
time_of_day
```

These describe event frequency and timing.

---

# 13. Example Feature Vector

A 10-minute behavior window might become:

```text
process_count                 = 35
unique_process_count          = 17
rare_process_count            = 4
powershell_count              = 8
encoded_command_count         = 3
network_event_count           = 14
unique_destinations           = 7
external_destinations         = 5
unique_users                  = 2
average_command_length        = 147
maximum_command_length        = 512
events_per_minute             = 50
processes_per_minute          = 3
parent_child_anomalies        = 2
```

This becomes a numerical vector:

```text
X = [
    35,
    17,
    4,
    8,
    3,
    14,
    7,
    5,
    2,
    147,
    512,
    50,
    3,
    2
]
```

The actual final feature list should be determined after examining the real event fields available in the NightOwl corpus.

---

# 14. ML Training Workflow

The recommended unsupervised training workflow is:

```text
             BENIGN / NORMAL TELEMETRY
                       |
                       v
                 EVTX Parsing
                       |
                       v
                 Normalization
                       |
                       v
                Feature Extraction
                       |
                       v
                 Feature Matrix
                       |
                       v
               Preprocessing
                       |
                       v
              ISOLATION FOREST
                       |
                       v
                 Trained Model
                       |
                       v
                  model file
```

The primary training data should represent normal Windows behavior.

---

# 15. Important Dataset Rule

Do not assume:

```text
detected = malicious
undetected = benign
```

That is incorrect.

The NightOwl documentation describes the detected/undetected directories as benchmark outputs that are re-derived by the detection benchmark scripts. They are not automatically ML labels.

For the unsupervised approach:

```text
TRAINING:
Primarily normal/benign behavior

TESTING:
Benign + malicious/attack behavior
```

Attack captures are particularly useful for evaluating whether the trained anomaly detector assigns higher anomaly scores to attack behavior.

---

# 16. Testing Workflow

After training:

```text
Attack EVTX
    |
    v
Parse
    |
    v
Normalize
    |
    v
Feature Extraction
    |
    v
Isolation Forest
    |
    v
Anomaly Score
    |
    v
Evaluate
```

Test on both:

```text
BENIGN DATA
+
ATTACK DATA
```

The goal is to determine whether malicious behavior tends to receive higher anomaly scores than benign behavior.

---

# 17. Threshold Selection

Isolation Forest produces an anomaly/outlier signal.

NightOwl should convert this into an operational category.

Conceptually:

```text
             ANOMALY SCORE
                   |
       +-----------+-----------+
       |           |           |
       v           v           v
     Normal    Suspicious    High
```

Do not permanently choose arbitrary thresholds before testing.

Instead:

1. Train the model.
2. Run it on validation data.
3. Inspect score distributions.
4. Measure false positives.
5. Measure attack detection.
6. Select thresholds based on evidence.
7. Re-test on unseen data.

This follows NightOwl's existing project philosophy of measuring detection behavior against real data.

---

# 18. ML Alert Structure

A new ML alert can conceptually contain:

```text
ML Alert
---------------------------
Detection Method:
ML_ANOMALY

Host:
WORKSTATION-01

Behavior Window:
10:00 - 10:10

Anomaly Score:
High

Evidence:
- Unusual process activity
- Unusual PowerShell frequency
- External network activity
- Rare process relationship
```

The exact database/API schema should be designed to fit NightOwl's existing `alerts` and `incidents` architecture.

---

# 19. Combining ML and Sigma

This is the key benefit of the hybrid approach.

Example:

```text
                    HOST-01
                       |
             +---------+---------+
             |                   |
             v                   v
        SIGMA ALERT          ML ALERT
             |                   |
   Known suspicious        Unusual behavior
      PowerShell                |
             |              Score: High
             |                   |
             +---------+---------+
                       |
                       v
                 CORRELATION
                       |
                       v
                   INCIDENT
```

A single incident can therefore contain evidence from multiple detection mechanisms.

---

# 20. Example Scenario

Suppose an attacker executes:

```text
Word
 |
 v
PowerShell
 |
 v
Encoded command
 |
 v
Network connection
 |
 v
Certutil
```

### Sigma may detect:

```text
Suspicious PowerShell
```

### Isolation Forest may detect:

```text
Unusual process chain
+
unusual PowerShell frequency
+
unusual network activity
```

### Correlation produces:

```text
Incident #42

Sigma Evidence:
Suspicious PowerShell

ML Evidence:
High behavioral anomaly

Host:
WORKSTATION-01
```

This is much stronger than either detector alone.

---

# 21. MITRE ATT&CK Enrichment

Existing NightOwl MITRE mapping remains useful.

For deterministic Sigma detections:

```text
Sigma Rule
    |
    v
MITRE Technique
```

For an ML anomaly:

```text
ML anomaly
    |
    v
Behavioral evidence
    |
    v
Potential technique context
```

Do not automatically assign a MITRE technique to an anomaly simply because its score is high.

The technique mapping should be evidence-based.

---

# 22. RAG Workflow

Once the incident exists:

```text
Incident
   |
   +-- Sigma evidence
   +-- ML evidence
   +-- Sequence evidence
   +-- Events
   +-- Process information
   +-- Command line
   +-- User
   +-- MITRE techniques
          |
          v
      RAG Retrieval
          |
          v
   Relevant MITRE/Playbook
       knowledge
```

NightOwl already uses a ChromaDB vector store containing MITRE technique descriptions and playbooks.

---

# 23. LLM Explanation Workflow

The existing LLM layer can then use:

```text
Incident Context
       +
ML Anomaly Information
       +
Sigma Evidence
       +
MITRE Context
       +
Retrieved RAG Chunks
       |
       v
      LLM
       |
       v
Explanation
       +
Recommendation
       +
Fact/Inference/Uncertainty
```

Example:

```text
FACT:
PowerShell was launched from the observed parent process.

FACT:
The behavior window received a high ML anomaly score.

FACT:
The event generated a Sigma alert.

INFERENCE:
The combination may indicate suspicious execution.

UNCERTAINTY:
Available telemetry does not independently prove malicious intent.

RECOMMENDATION:
Investigate the parent process, command line,
and network destinations.
```

---

# 24. Final Dashboard Workflow

The SOC analyst should see:

```text
+--------------------------------------------------+
|                 NIGHTOWL                         |
+--------------------------------------------------+
| INCIDENT #42                                     |
|                                                  |
| Host: WORKSTATION-01                            |
| Severity: HIGH                                  |
|                                                  |
| Detection Sources:                              |
|   [Sigma] Suspicious PowerShell                 |
|   [ML]    High Behavioral Anomaly               |
|                                                  |
| ML Anomaly: HIGH                                |
|                                                  |
| MITRE ATT&CK: T1059.001                         |
|                                                  |
| Evidence Timeline                               |
| -----------------------------------------------  |
| Word -> PowerShell -> Network -> Certutil       |
|                                                  |
| AI Investigation                                |
| -----------------------------------------------  |
| Explanation                                     |
| Fact / Inference / Uncertainty                  |
| Recommended Response                            |
+--------------------------------------------------+
```

---

# 25. Complete ML Workflow Diagram

```text
                    +----------------+
                    |    EVTX FILE   |
                    +-------+--------+
                            |
                            v
                   +------------------+
                   | EVTX PARSER      |
                   +--------+---------+
                            |
                            v
                   +------------------+
                   | NORMALIZATION    |
                   +--------+---------+
                            |
                            v
                   +------------------+
                   | EVENTS           |
                   | host             |
                   | timestamp        |
                   | process          |
                   | parent_process   |
                   | command_line     |
                   | user             |
                   | event_data       |
                   +--------+---------+
                            |
                            v
                   +------------------+
                   | HOST BEHAVIOR    |
                   | WINDOW           |
                   | 5–10 minutes     |
                   +--------+---------+
                            |
                            v
                   +------------------+
                   | FEATURE ENGINE   |
                   +--------+---------+
                            |
            +---------------+---------------+
            |               |               |
            v               v               v
        Process          Network        Command
        Features         Features       Features
            |               |               |
            +---------------+---------------+
                            |
                            v
                   +------------------+
                   | FEATURE VECTOR   |
                   +--------+---------+
                            |
                            v
                   +------------------+
                   | ISOLATION FOREST |
                   | UNSUPERVISED ML  |
                   +--------+---------+
                            |
                            v
                   +------------------+
                   | ANOMALY SCORE    |
                   +--------+---------+
                            |
                     +------+------+
                     |             |
                     v             v
                  Normal       Anomaly
                                   |
                                   v
                              ML ALERT
```

---

# 26. Complete Hybrid Workflow Diagram

```text
                         EVTX
                          |
                          v
                     INGESTION
                          |
                          v
                    NORMALIZER
                          |
                          v
                  NORMALIZED EVENTS
                          |
              +-----------+-----------+
              |                       |
              v                       v
       +-------------+         +-------------+
       | SIGMA       |         | ML FEATURE  |
       | ENGINE      |         | ENGINE      |
       +------+------+         +------+------+
              |                       |
              v                       v
       Known Threats          Behavioral Features
              |                       |
              |                       v
              |                +-------------+
              |                | ISOLATION   |
              |                | FOREST      |
              |                +------+------+
              |                       |
              |                       v
              |                Anomaly Score
              |                       |
              +-----------+-----------+
                          |
                          v
                    ALERT CORRELATION
                          |
                          v
                       INCIDENT
                          |
             +------------+------------+
             |                         |
             v                         v
       MITRE ATT&CK                 RAG
             |                         |
             +------------+------------+
                          |
                          v
                         LLM
                          |
                          v
                Explanation + Response
                          |
                          v
                     SOC CONSOLE
```

---

# 27. ML Training vs Detection-Time Workflow

These are two separate processes.

## Training

```text
Normal EVTX
    |
    v
Feature Extraction
    |
    v
Feature Matrix
    |
    v
Isolation Forest
    |
    v
Trained Model
    |
    v
Save Model
```

## Detection

```text
New EVTX
    |
    v
Feature Extraction
    |
    v
Saved Isolation Forest
    |
    v
Anomaly Score
    |
    v
ML Alert
```

The trained model does not need to be retrained for every uploaded EVTX file.

---

# 28. Recommended Software Architecture

A clean implementation can add an ML module to the backend:

```text
backend/
└── app/
    ├── api/
    ├── core/
    ├── detection/
    │   ├── rules/
    │   ├── engine.py
    │   └── sequences.py
    │
    ├── ml/
    │   ├── __init__.py
    │   ├── feature_extractor.py
    │   ├── anomaly_detector.py
    │   ├── model_manager.py
    │   └── scoring.py
    │
    ├── ingestion/
    ├── services/
    ├── rag/
    └── models/
```

### Responsibilities

`feature_extractor.py`

```text
Events
  ↓
Behavior windows
  ↓
Feature vectors
```

`anomaly_detector.py`

```text
Feature vectors
  ↓
Isolation Forest
  ↓
Anomaly scores
```

`model_manager.py`

```text
Train
Load
Save
Version
```

`scoring.py`

```text
Raw anomaly signal
  ↓
NightOwl anomaly category
```

The exact package names can be changed to match the repository's existing conventions.

---

# 29. Model Lifecycle

```text
          COLLECT NORMAL DATA
                  |
                  v
          FEATURE EXTRACTION
                  |
                  v
          TRAIN ISOLATION FOREST
                  |
                  v
              VALIDATE
                  |
        +---------+---------+
        |                   |
        v                   v
     Good?               Not Good?
        |                   |
        v                   v
   Save Model        Improve Features
        |                   |
        +---------+---------+
                  |
                  v
            DEPLOY MODEL
                  |
                  v
           DETECT ANOMALIES
                  |
                  v
           COLLECT FEEDBACK
                  |
                  v
        PERIODICALLY RETRAIN
```

Retraining should be controlled and evaluated rather than automatically changing the production model after every alert.

---

# 30. Evaluation Strategy

Do not evaluate the ML model using accuracy alone.

For anomaly detection, measure:

- False positives
- Detection rate / recall on attack test data
- Precision where ground-truth labels are available
- ROC-AUC or PR-AUC where appropriate
- Anomaly score distributions
- Detection latency
- Number of ML alerts generated
- Overlap between ML alerts and Sigma alerts
- Additional attacks/behaviors identified only by ML

A particularly important experiment is:

```text
Sigma only
      VS
Sigma + Isolation Forest
```

Compare whether the hybrid system finds additional suspicious behavior without creating an unacceptable number of false positives.

NightOwl already has benchmark scripts for measuring detection against its real-world fixture corpus, so the ML evaluation should be added as a separate ML evaluation rather than confusing it with the existing rule benchmark.

---

# 31. What Success Looks Like

The goal is not:

```text
ML detects everything
```

The goal is:

```text
             KNOWN THREATS
                  |
               SIGMA
                  |
                  v
               ALERTS


          UNUSUAL BEHAVIOR
                  |
           ISOLATION FOREST
                  |
                  v
               ANOMALIES


              BOTH
               |
               v
           CORRELATION
               |
               v
            INCIDENT
               |
               v
          RAG + LLM
               |
               v
       ANALYST EXPLANATION
```

The ML layer should provide **additional evidence**, especially for behavior that isn't represented by the current deterministic rules.

---

# 32. What Not to Do

### Do not replace Sigma.

Keep the existing 45 rules.

### Do not train on raw EVTX XML.

Convert events into meaningful behavioral features.

### Do not train on every attack capture as if it were normal.

The unsupervised model should learn normal behavior.

### Do not treat detected/undetected as ML labels.

That directory split belongs to the existing detection benchmark.

### Do not claim anomaly = malware.

An anomaly is a suspicious signal.

### Do not add many models initially.

Start with one Isolation Forest.

### Do not hard-code thresholds without evaluation.

Choose thresholds from validation experiments.

### Do not automatically map every anomaly to a MITRE technique.

Technique assignment must be supported by evidence.

---

# 33. Final Recommended Architecture

The final NightOwl system should be described as:

```text
             NIGHTOWL HYBRID SOC
                     |
     +---------------+---------------+
     |               |               |
     v               v               v
  RULE-BASED      UNSUPERVISED     KNOWLEDGE
  DETECTION           ML            ANALYSIS
     |               |               |
  Sigma +          Isolation       RAG +
  Sequences         Forest          LLM
     |               |               |
     +-------+-------+               |
             |                       |
             v                       |
         CORRELATION <---------------+
             |
             v
          INCIDENT
             |
             v
       MITRE ATT&CK
             |
             v
       SOC EXPLANATION
             |
             v
          ANALYST
```

---

# 34. One-Line Project Definition

> **NightOwl is a hybrid Windows SOC investigation platform that combines deterministic Sigma-based detection, unsupervised Isolation Forest behavioral anomaly detection, incident correlation, MITRE ATT&CK enrichment, and grounded RAG/LLM analysis to help analysts identify and investigate both known and unusual Windows activity.**

---

# 35. Key Points to Remember

| Question | Answer |
|---|---|
| ML type | **Unsupervised Learning** |
| Algorithm | **Isolation Forest** |
| ML task | **Behavioral anomaly detection** |
| Primary training data | **Normal/benign Windows telemetry** |
| Attack data | **Evaluation/testing** |
| Initial number of ML models | **1** |
| Input | Engineered behavioral feature vectors |
| Recommended window | **5–10 minutes per host initially** |
| Output | Anomaly/outlier score + anomaly category |
| Existing Sigma rules | **Keep them** |
| Existing sequence engine | **Keep it** |
| MITRE | **Keep it** |
| RAG | **Keep it** |
| LLM | **Keep it** |
| Main benefit | Detect unusual behavior not covered by deterministic rules |
| ML replaces Sigma? | **No** |
| Anomaly automatically means malware? | **No** |

---

# 36. Final Concept

The entire idea can be remembered with four words:

```text
DETECT → CORRELATE → EXPLAIN → INVESTIGATE
```

**Sigma + Isolation Forest**

↓

**Alerts + Anomalies**

↓

**Incident Correlation**

↓

**MITRE + RAG + LLM**

↓

**SOC Analyst**

This is the recommended ML enhancement for the existing NightOwl project.

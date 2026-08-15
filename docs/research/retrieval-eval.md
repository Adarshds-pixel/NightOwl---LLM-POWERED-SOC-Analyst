# Day 5 Retrieval Quality Check (Pair 2)

Manual evaluation of `backend/app/rag/retriever.py`'s `retrieve()` against the
real `knowledge_base` Chroma collection (1888 chunks: 697 MITRE techniques +
5 playbooks, per Day 4's `build_kb.py` run). For each query, `retrieve(query, k=4)`
was run for real (see command below) and the top-4 chunks + scores recorded.
Score = `1 / (1 + L2 distance)`, higher is better.

Reproduce with:
```
cd backend
./venv/Scripts/python.exe -c "
from app.rag.retriever import retrieve
for h in retrieve('<query>', k=4):
    print(h['score'], h['chunk_id'], h['metadata'].get('technique_name') or h['metadata'].get('title'))
"
```

## Results

### 1. "PowerShell execution with encoded command"
| Score | Chunk | Source |
|---|---|---|
| 0.5085 | mitre:T1027.010:1 | Command Obfuscation |
| 0.4910 | mitre:T1059.001:0 | PowerShell |
| 0.4841 | playbook:T1059_001_powershell_execution:0 | PowerShell playbook |
| 0.4824 | playbook:T1059_001_powershell_execution:2 | PowerShell playbook |
**Verdict: good.** Correct technique + its own playbook both surfaced.

### 2. "scheduled task created for persistence"
Top hits: playbook:T1053_005_scheduled_task_persistence (x3), mitre:T1053.005 (0.62-0.60).
**Verdict: good.** Exact technique/playbook match, high scores.

### 3. "beaconing to command and control server over HTTPS"
Top hits: mitre:T1071.005 Pub/Sub Protocols (0.46), mitre:T1608.003 Install Digital Certificate (0.45), mitre:T1608 Stage Capabilities (0.45). T1071.001 (Web Protocols, the technically correct match) only appears at rank 9 (score 0.4435); the `T1071_001_web_protocol_c2` playbook doesn't appear until rank 47 of 1888 (score 0.42, confirmed by re-running with k=1888) — well outside any practical top-k.
**Verdict: partial/weak.** See "Issue found" below.

### 4. "registry run key added for persistence"
Top hits: mitre:T1547.001 (0.65), playbook:T1547_001_registry_run_key_persistence (0.62), mitre:T1547.001 more chunks (0.54, 0.52).
**Verdict: good.**

### 5. "credential dumping from LSASS memory"
Top hits: mitre:T1003.001 LSASS Memory (0.70), playbook:T1003_credential_dumping (0.60), mitre:T1003.004 LSA Secrets (0.60), playbook:T1003_credential_dumping (0.59).
**Verdict: good.**

### 6. "encoded PowerShell command line"
Top hits: mitre:T1027.010 Command Obfuscation (0.51), mitre:T1546.013 PowerShell Profile (0.48, tangential), mitre:T1059.001 PowerShell (0.48), playbook:T1059_001 (0.47).
**Verdict: good, one tangential hit.** T1546.013 isn't wrong (it's PowerShell-related) but isn't the best match for "encoded command line" specifically — minor noise, not a failure.

### 7. "suspicious scheduled task created for persistence"
Top hits: all playbook:T1053_005_scheduled_task_persistence chunks (0.68, 0.62, 0.58), then playbook:T1547_001 (0.54).
**Verdict: good.** Best result of the whole eval — near-exact analyst phrasing of the playbook's own scenario.

### 8. "beaconing over HTTPS to external IP"
Top hits: mitre:T1090.001 Internal Proxy (0.46), mitre:T1090.004 Domain Fronting (0.44), mitre:T1599.001 NAT Traversal (0.44), mitre:T1608.003 Install Digital Certificate (0.44).
**Verdict: bad.** None of the top 4 are the right technique family (T1071.001 Web Protocols) or the C2 playbook; T1071.001 doesn't appear in the top 20 at all for this phrasing. Same root cause as query 3.

### 9. "LSASS memory access"
Top hits: mitre:T1003.001 LSASS Memory (0.66), mitre:T1547.008 LSASS Driver (0.55, related), mitre:T1547.008 (0.55), mitre:T1003.001 more chunks (0.54).
**Verdict: good.**

### 10. "new registry run key added by unsigned binary"
Top hits: mitre:T1547.001 (0.53), playbook:T1547_001_registry_run_key_persistence (0.52), mitre:T1218.009 Regsvcs/Regasm (0.51, tangential — signed-binary proxy execution, picked up on "unsigned binary" wording), mitre:T1547.001 more chunks (0.51).
**Verdict: good, one tangential hit.**

## Issue found: "beaconing" queries under-retrieve the C2 playbook

Queries 3 and 8 (both about C2 beaconing over HTTPS) failed to surface either
the correct technique (T1071.001 Web Protocols) or its playbook
(`T1071_001_web_protocol_c2.md`) in a practical top-k. This was confirmed not
to be an ingestion bug — the playbook's 3 chunks are present in the collection
(`collection.get(where={"source_file": "T1071_001_web_protocol_c2.md"})`
returns them, content on-topic) — it's a genuine embedding-similarity gap:
even the query "HTTPS web protocol command and control" (near-exact technique
name) doesn't surface the playbook chunk in the top 20 of 1888. Related but
generic MITRE techniques (Pub/Sub Protocols, Domain Fronting, Install Digital
Certificate) score higher, likely because they share more surface vocabulary
("protocol", "HTTPS", "certificate") with the query than the playbook's more
narrative, analyst-oriented phrasing does.

**Everything else tested (8/10 queries) retrieved good-to-tangential results**,
so `all-MiniLM-L6-v2` (chosen in Day 3 for CPU speed, see `embeddings.py`)
does not need to be swapped out wholesale. But the C2/network-category
content is the weak spot so far. Two follow-ups worth doing once real
incidents exist (per the roadmap's Day 7+ generation work):
- When building the explanation prompt (Day 7), don't rely on free-text
  incident summaries alone for the retrieval query — pass the matched
  technique ID too (e.g. filter/boost with `technique_id="T1071.001"`) when
  it's already known from Sigma-rule matching, rather than retrieving on
  natural-language description alone.
- If C2-category explanations still read poorly once real incidents flow in
  (~Day 8), consider adding more C2-specific playbook content (more chunks,
  more of the analyst vocabulary used in query 8) rather than swapping
  embedding models, since 8/10 categories retrieve well with the current model.

## Summary
`retrieve()` returns ranked, filterable (by `source_type`/`technique_id`)
top-k chunks with sensible scores. 8 of 10 test queries retrieved
good-to-acceptable results; the C2/beaconing category is a known weak spot,
documented above for Day 7+ to account for rather than something to fix in
the retriever itself (the retriever is doing its job correctly — it's a
content/embedding-similarity gap specific to that category, not a bug).

"""Day 5 verification (Pair 2): retriever.py returns ranked, filterable
top-k chunks from the real "knowledge_base" Chroma collection built on
Day 4. Network-dependent (loads the sentence-transformers model) and
requires data/chroma to already be populated by scripts/build_kb.py.
"""

import pytest

from app.rag.retriever import retrieve

pytestmark = pytest.mark.integration


def test_retrieve_returns_k_results_ranked_by_score():
    hits = retrieve("obfuscated powershell encoded command", k=5)
    assert len(hits) == 5
    scores = [hit["score"] for hit in hits]
    assert scores == sorted(scores, reverse=True)
    assert any(hit["metadata"]["source_type"] in ("mitre_technique", "playbook") for hit in hits)


def test_retrieve_technique_id_filter_restricts_results():
    hits = retrieve("execution", k=5, technique_id="T1059.001")
    assert len(hits) > 0
    assert all(hit["metadata"]["technique_id"] == "T1059.001" for hit in hits)


def test_retrieve_source_type_filter_restricts_results():
    hits = retrieve("credential dumping", k=5, source_type="playbook")
    assert len(hits) > 0
    assert all(hit["metadata"]["source_type"] == "playbook" for hit in hits)

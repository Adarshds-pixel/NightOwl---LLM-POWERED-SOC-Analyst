"""Day 3 verification (Pair 2): ChromaDB add/query, embedding model, MITRE loader.

The Chroma and embedding checks download models, so they are `integration`
tests (run with `pytest -m integration`); the Chroma one uses an in-memory
client so it never writes into the real knowledge-base store. The MITRE
loader check reads the vendored ATT&CK index and runs offline.
"""

import chromadb
import pytest

from app.mitre.loader import load_mitre_tactics, load_mitre_techniques


@pytest.mark.integration
def test_chroma_add_and_query():
    collection = chromadb.EphemeralClient().get_or_create_collection("day3_smoke_test")
    collection.upsert(
        ids=["doc1", "doc2"],
        documents=[
            "Suspicious PowerShell execution with encoded command line",
            "Scheduled task created for persistence",
        ],
    )
    results = collection.query(query_texts=["obfuscated powershell command"], n_results=1)
    assert results["ids"][0][0] == "doc1"


@pytest.mark.integration
def test_embedding_shape():
    from app.rag.embeddings import embed_text

    vector = embed_text("suspicious powershell execution")
    assert len(vector) == 384
    assert all(isinstance(v, float) for v in vector)


def test_mitre_loader_has_known_technique():
    techniques = load_mitre_techniques()
    assert len(techniques) > 500
    assert "T1059.001" in techniques
    assert techniques["T1059.001"]["name"]
    assert "PowerShell" in techniques["T1059.001"]["name"]


def test_mitre_loader_exposes_the_release_tactics():
    tactics = load_mitre_tactics()
    assert "credential-access" in tactics
    # ATT&CK v19 split defense-evasion into these two.
    assert {"stealth", "defense-impairment"} <= set(tactics)
    assert "defense-evasion" not in tactics

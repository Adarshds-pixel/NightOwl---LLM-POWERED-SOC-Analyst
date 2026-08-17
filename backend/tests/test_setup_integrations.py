"""Day 3 verification (Pair 2): ChromaDB add/query, embedding model, MITRE loader."""

from app.mitre.loader import load_mitre_techniques
from app.rag.chroma_client import get_or_create_collection
from app.rag.embeddings import embed_text


def test_chroma_add_and_query():
    collection = get_or_create_collection("day3_smoke_test")
    collection.upsert(
        ids=["doc1", "doc2"],
        documents=[
            "Suspicious PowerShell execution with encoded command line",
            "Scheduled task created for persistence",
        ],
    )
    results = collection.query(query_texts=["obfuscated powershell command"], n_results=1)
    assert results["ids"][0][0] == "doc1"


def test_embedding_shape():
    vector = embed_text("suspicious powershell execution")
    assert len(vector) == 384
    assert all(isinstance(v, float) for v in vector)


def test_mitre_loader_has_known_technique():
    techniques = load_mitre_techniques()
    assert len(techniques) > 500
    assert "T1059.001" in techniques
    assert techniques["T1059.001"]["name"]
    assert "PowerShell" in techniques["T1059.001"]["name"]

"""Top-k retrieval against the "knowledge_base" Chroma collection.

Queries are embedded with our own sentence-transformers wrapper (embed_text)
rather than passed as query_texts, so the query vector comes from the exact
same model used to embed the chunks in build_kb.py -- relying on Chroma's
implicit default embedding function here would risk a mismatched model.
"""

import logging

from app.rag.chroma_client import get_or_create_collection
from app.rag.embeddings import embed_text

KB_COLLECTION_NAME = "knowledge_base"

logger = logging.getLogger(__name__)


def retrieve(
    query: str,
    k: int = 5,
    source_type: str | None = None,
    technique_id: str | None = None,
    technique_ids: list[str] | None = None,
) -> list[dict]:
    """Return the top-k chunks most relevant to `query`, each as a dict with
    chunk_id, document, metadata, and score (higher score = more relevant).

    Chroma returns raw L2 distances (lower = closer); we convert to
    1 / (1 + distance) so callers get an intuitive "higher is better" score
    instead of having to know the underlying distance metric.
    """
    collection = get_or_create_collection(KB_COLLECTION_NAME)
    if collection.count() == 0:
        logger.warning(
            "knowledge base is empty -- run `python ai/tools/build_kb.py`; answers will have no retrieval grounding"
        )
        return []
    ids_filter = [t for t in (technique_ids or []) if t]
    if technique_id and technique_id not in ids_filter:
        ids_filter.insert(0, technique_id)
    clauses = []
    if source_type:
        clauses.append({"source_type": source_type})
    if len(ids_filter) == 1:
        clauses.append({"technique_id": ids_filter[0]})
    elif ids_filter:
        clauses.append({"technique_id": {"$in": ids_filter}})
    where = None if not clauses else clauses[0] if len(clauses) == 1 else {"$and": clauses}

    results = collection.query(
        query_embeddings=[embed_text(query)],
        n_results=k,
        where=where,
    )

    ids = results["ids"][0]
    documents = results["documents"][0]
    metadatas = results["metadatas"][0]
    distances = results["distances"][0]

    return [
        {
            "chunk_id": chunk_id,
            "document": document,
            "metadata": metadata,
            "score": 1 / (1 + distance),
        }
        for chunk_id, document, metadata, distance in zip(ids, documents, metadatas, distances)
    ]


if __name__ == "__main__":
    hits = retrieve("obfuscated powershell command line", k=3)
    for hit in hits:
        print(f"{hit['score']:.4f}  {hit['chunk_id']}  {hit['document'][:80]!r}")

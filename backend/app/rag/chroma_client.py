"""Local, in-process ChromaDB client wiring.

Uses PersistentClient (file-backed, no separate server process) so the
whole project stays $0 / zero-extra-infra — no Chroma server to run or
manage. If concurrent multi-process access is ever needed, swapping to
HttpClient later only changes the client construction, not the collection
API used elsewhere (get_or_create_collection/add/query).
"""

from pathlib import Path

import chromadb

CHROMA_PERSIST_DIR = Path(__file__).resolve().parents[3] / "data" / "chroma"


def get_client() -> chromadb.ClientAPI:
    CHROMA_PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(CHROMA_PERSIST_DIR))


def get_or_create_collection(name: str, client: chromadb.ClientAPI | None = None):
    client = client or get_client()
    return client.get_or_create_collection(name=name)


if __name__ == "__main__":
    # Manual smoke test: add two docs, query for the closer one.
    collection = get_or_create_collection("day3_smoke_test")
    collection.upsert(
        ids=["doc1", "doc2"],
        documents=[
            "Suspicious PowerShell execution with encoded command line",
            "Scheduled task created for persistence",
        ],
    )
    results = collection.query(query_texts=["obfuscated powershell command"], n_results=1)
    print("Query result:", results["documents"])

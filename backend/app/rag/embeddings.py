"""Sentence embedding wiring for the RAG pipeline.

Model: all-MiniLM-L6-v2 (384-dim). Chosen over larger models (e.g.
all-mpnet-base-v2) for CPU speed and small download size, which fits a
student laptop with no GPU. Revisit only if Day 5's retrieval-quality
check shows it's insufficient.
"""

from sentence_transformers import SentenceTransformer

MODEL_NAME = "all-MiniLM-L6-v2"

_model: SentenceTransformer | None = None


def get_embedding_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def embed_text(text: str) -> list[float]:
    return get_embedding_model().encode(text).tolist()


def embed_texts(texts: list[str]) -> list[list[float]]:
    return get_embedding_model().encode(texts).tolist()


if __name__ == "__main__":
    vector = embed_text("suspicious powershell execution")
    print(f"Embedding dim: {len(vector)}")
    print(f"First 5 values: {vector[:5]}")

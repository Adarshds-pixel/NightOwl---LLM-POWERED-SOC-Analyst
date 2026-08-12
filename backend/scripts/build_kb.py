"""Knowledge base ingestion: chunk MITRE technique docs + playbooks, embed, store in Chroma.

Run for real from backend/: `python scripts/build_kb.py`

Sources:
  - MITRE ATT&CK technique descriptions (via app.mitre.loader), excluding
    deprecated/revoked techniques -- explaining a live incident with a
    deprecated technique's writeup isn't useful grounding.
  - Response playbooks authored under data/knowledge_base/playbooks/*.md.

Chunks are embedded with our own sentence-transformers wrapper (not
Chroma's implicit default embedding function) so the vectors are produced
by the same model the rest of the RAG pipeline uses, and stored in a single
"knowledge_base" collection that Day 5's retriever.py will query.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/

from app.mitre.loader import load_mitre_techniques  # noqa: E402
from app.rag.chroma_client import get_or_create_collection  # noqa: E402
from app.rag.embeddings import embed_texts  # noqa: E402

KB_COLLECTION_NAME = "knowledge_base"
PLAYBOOKS_DIR = Path(__file__).resolve().parents[2] / "data" / "knowledge_base" / "playbooks"

CHUNK_MAX_CHARS = 800
CHUNK_OVERLAP = 100


def chunk_text(text: str, max_chars: int = CHUNK_MAX_CHARS, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split text into overlapping chunks, breaking on paragraph/sentence
    boundaries where possible. Text shorter than max_chars is returned as a
    single chunk unchanged -- most MITRE descriptions and playbook sections
    fit in one chunk already."""
    text = text.strip()
    if len(text) <= max_chars:
        return [text] if text else []

    # Prefer splitting on paragraph breaks, falling back to sentences.
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    units = paragraphs if len(paragraphs) > 1 else re.split(r"(?<=[.!?])\s+", text)

    chunks: list[str] = []
    current = ""
    for unit in units:
        candidate = f"{current} {unit}".strip() if current else unit
        if len(candidate) <= max_chars:
            current = candidate
            continue
        if current:
            chunks.append(current)
        current = unit
        # A single unit longer than max_chars: hard-split it.
        while len(current) > max_chars:
            chunks.append(current[:max_chars])
            current = current[max_chars - overlap:]
    if current:
        chunks.append(current)

    # Apply overlap between adjacent chunks so context isn't lost at boundaries.
    overlapped = []
    for i, chunk in enumerate(chunks):
        if i == 0:
            overlapped.append(chunk)
        else:
            prefix = chunks[i - 1][-overlap:]
            overlapped.append(f"{prefix} {chunk}".strip())
    return overlapped


def build_mitre_chunks() -> tuple[list[str], list[str], list[dict], int, int]:
    techniques = load_mitre_techniques()
    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict] = []
    skipped = 0

    for tech_id, tech in techniques.items():
        if tech["is_deprecated"] or tech["is_revoked"]:
            skipped += 1
            continue
        text = f"{tech['name']}\n\n{tech['description']}"
        for idx, chunk in enumerate(chunk_text(text)):
            ids.append(f"mitre:{tech_id}:{idx}")
            documents.append(chunk)
            metadatas.append(
                {
                    "source_type": "mitre_technique",
                    "technique_id": tech_id,
                    "technique_name": tech["name"],
                    "tactics": ", ".join(tech["tactics"]),
                }
            )

    processed = len(techniques) - skipped
    return ids, documents, metadatas, processed, skipped


def _parse_playbook(path: Path) -> tuple[str, str, str]:
    """Parse the '# Title' / 'Technique: <id>' header convention. Returns
    (title, technique_id, body)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    title = lines[0].lstrip("#").strip() if lines and lines[0].startswith("#") else path.stem
    technique_id = ""
    body_start = 1
    for i, line in enumerate(lines[1:3], start=1):
        match = re.match(r"Technique:\s*(\S+)", line)
        if match:
            technique_id = match.group(1)
            body_start = i + 1
            break
    body = "\n".join(lines[body_start:]).strip()
    return title, technique_id, body


def build_playbook_chunks() -> tuple[list[str], list[str], list[dict], int]:
    ids: list[str] = []
    documents: list[str] = []
    metadatas: list[dict] = []
    processed = 0

    for path in sorted(PLAYBOOKS_DIR.glob("*.md")):
        title, technique_id, body = _parse_playbook(path)
        slug = path.stem
        for idx, chunk in enumerate(chunk_text(body)):
            ids.append(f"playbook:{slug}:{idx}")
            documents.append(f"{title}\n\n{chunk}")
            metadatas.append(
                {
                    "source_type": "playbook",
                    "technique_id": technique_id,
                    "title": title,
                    "source_file": path.name,
                }
            )
        processed += 1

    return ids, documents, metadatas, processed


def build_kb() -> None:
    mitre_ids, mitre_docs, mitre_meta, mitre_processed, mitre_skipped = build_mitre_chunks()
    pb_ids, pb_docs, pb_meta, pb_processed = build_playbook_chunks()

    ids = mitre_ids + pb_ids
    documents = mitre_docs + pb_docs
    metadatas = mitre_meta + pb_meta

    print(f"MITRE techniques: {mitre_processed} processed, {mitre_skipped} skipped (deprecated/revoked)")
    print(f"Playbooks: {pb_processed} processed")
    print(f"Total chunks to embed: {len(documents)}")

    embeddings = embed_texts(documents)

    collection = get_or_create_collection(KB_COLLECTION_NAME)
    # Chroma upsert has a practical batch-size limit; write in batches to be safe.
    batch_size = 500
    for start in range(0, len(ids), batch_size):
        end = start + batch_size
        collection.upsert(
            ids=ids[start:end],
            documents=documents[start:end],
            embeddings=embeddings[start:end],
            metadatas=metadatas[start:end],
        )

    print(f"Upserted {len(ids)} chunks into Chroma collection '{KB_COLLECTION_NAME}' ({collection.count()} total in collection).")


if __name__ == "__main__":
    build_kb()

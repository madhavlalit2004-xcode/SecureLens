"""Small, local RAG layer for SecureLens.

The implementation is intentionally dependency-light for local development. It
uses transparent lexical retrieval and returns source metadata so every agent
can cite the policy passage it used. A vector store can replace `search`
without changing the agent contract.
"""
from dataclasses import dataclass
import json
import re
from uuid import uuid4

from app.database import connection, initialize_database
from app.llm import embed_text


@dataclass(frozen=True)
class KnowledgeChunk:
    source_id: str
    title: str
    framework: str
    content: str


@dataclass(frozen=True)
class RetrievedContext:
    source_id: str
    title: str
    framework: str
    excerpt: str
    score: int


DEFAULT_KNOWLEDGE: tuple[KnowledgeChunk, ...] = (
    KnowledgeChunk("asvs-v6-4", "Protect sensitive data", "OWASP ASVS", "Store secrets outside source code and rotate credentials that may have been exposed."),
    KnowledgeChunk("asvs-v9-1", "Secure communications", "OWASP ASVS", "Protect data in transit using TLS and validate certificates. Do not use cleartext HTTP for production services."),
    KnowledgeChunk("asvs-v14-5", "Browser security controls", "OWASP ASVS", "Restrict cross-origin access to explicitly trusted origins and avoid wildcard CORS for authenticated applications."),
    KnowledgeChunk("ssdf-pw6", "Release hardening", "NIST SSDF", "Configure production releases securely. Disable debug features and verify secure defaults before deployment."),
    KnowledgeChunk("stride-tampering", "STRIDE: tampering", "Threat modeling", "Unverified transport can permit an attacker on the network path to alter requests or responses."),
    KnowledgeChunk("stride-disclosure", "STRIDE: information disclosure", "Threat modeling", "Credentials included in technical artefacts can be copied, abused, and used to access protected systems."),
)


def _terms(value: str) -> set[str]:
    return set(re.findall(r"[a-z]{3,}", value.lower()))


def retrieve(query: str, frameworks: list[str], limit: int = 4) -> list[RetrievedContext]:
    """Return relevant, inspectable policy context for an assessment."""
    requested = {framework.lower() for framework in frameworks}
    query_terms = _terms(query)
    ranked: list[RetrievedContext] = []
    for chunk in DEFAULT_KNOWLEDGE:
        if chunk.framework.lower() not in requested and chunk.framework != "Threat modeling":
            continue
        score = len(query_terms & _terms(f"{chunk.title} {chunk.content}"))
        if score:
            ranked.append(RetrievedContext(chunk.source_id, chunk.title, chunk.framework, chunk.content, score))
    initialize_database()
    stored = _retrieve_stored(query, frameworks, limit)
    return (stored + sorted(ranked, key=lambda item: (-item.score, item.source_id)))[:limit]


def _chunks(content: str, size: int = 900, overlap: int = 120) -> list[str]:
    normalized = re.sub(r"\s+", " ", content).strip()
    return [normalized[index:index + size] for index in range(0, len(normalized), size - overlap) if normalized[index:index + size]]


def add_document(filename: str, framework: str, content: str) -> tuple[str, int]:
    """Persist a policy document and its local embedding vectors when available."""
    initialize_database()
    document_id = f"kb_{uuid4().hex[:12]}"
    chunks = _chunks(content)
    with connection() as db:
        db.execute("INSERT INTO knowledge_documents (document_id, filename, framework, content) VALUES (?, ?, ?, ?)", (document_id, filename, framework, content))
        for chunk in chunks:
            vector = embed_text(chunk)
            db.execute("INSERT INTO knowledge_chunks (chunk_id, document_id, content, embedding) VALUES (?, ?, ?, ?)", (f"chunk_{uuid4().hex[:12]}", document_id, chunk, json.dumps(vector) if vector else None))
    return document_id, len(chunks)


def _cosine(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right))
    left_size = sum(a * a for a in left) ** 0.5
    right_size = sum(b * b for b in right) ** 0.5
    return dot / (left_size * right_size) if left_size and right_size else 0


def _retrieve_stored(query: str, frameworks: list[str], limit: int) -> list[RetrievedContext]:
    requested = {item.lower() for item in frameworks}
    query_vector = embed_text(query)
    query_terms = _terms(query)
    with connection() as db:
        rows = db.execute("SELECT c.chunk_id, c.content, c.embedding, d.filename, d.framework FROM knowledge_chunks c JOIN knowledge_documents d ON c.document_id = d.document_id").fetchall()
    scored: list[RetrievedContext] = []
    for row in rows:
        if row["framework"].lower() not in requested:
            continue
        vector = json.loads(row["embedding"]) if row["embedding"] else None
        score = int(_cosine(query_vector, vector) * 1000) if query_vector and vector else len(query_terms & _terms(row["content"]))
        if score:
            scored.append(RetrievedContext(row["chunk_id"], row["filename"], row["framework"], row["content"][:360], score))
    return sorted(scored, key=lambda item: (-item.score, item.source_id))[:limit]

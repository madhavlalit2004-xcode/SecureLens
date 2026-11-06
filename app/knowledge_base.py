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
    version: str | None = None
    control_id: str | None = None
    source_url: str | None = None


@dataclass(frozen=True)
class RetrievedContext:
    source_id: str
    title: str
    framework: str
    excerpt: str
    score: int
    version: str | None = None
    control_id: str | None = None
    source_url: str | None = None


ASVS_5 = "https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv"
SSDF_1_1 = "https://csrc.nist.gov/pubs/sp/800/218/final"

DEFAULT_KNOWLEDGE: tuple[KnowledgeChunk, ...] = (
    KnowledgeChunk("asvs-5-v13-3-1", "Secrets management", "OWASP ASVS", "Use a secrets management solution to create, store, control access to, and destroy backend secrets. Keep secrets out of source code and build artifacts.", "5.0.0", "V13.3.1", ASVS_5),
    KnowledgeChunk("asvs-5-v13-4-2", "Production debug settings", "OWASP ASVS", "Disable debug modes for every component in production to prevent debug feature exposure and information leakage.", "5.0.0", "V13.4.2", ASVS_5),
    KnowledgeChunk("asvs-5-v3-4-2", "CORS origin validation", "OWASP ASVS", "Set Access-Control-Allow-Origin to a fixed value, or validate a request Origin against an allowlist of trusted origins. If wildcard access is needed, ensure responses do not expose sensitive information.", "5.0.0", "V3.4.2", ASVS_5),
    KnowledgeChunk("asvs-5-v12-2-1", "TLS for external services", "OWASP ASVS", "Use TLS for client connections to external-facing HTTP services.", "5.0.0", "V12.2.1", ASVS_5),
    KnowledgeChunk("asvs-5-v12-3-2", "TLS certificate validation", "OWASP ASVS", "TLS clients should validate server certificates so they can authenticate the intended service.", "5.0.0", "V12.3.2", ASVS_5),
    KnowledgeChunk("ssdf-1-1-pw1-1", "Risk modeling", "NIST SSDF", "Use threat modeling and analysis of attacks and attack surfaces to identify and assess software security risks.", "1.1", "PW.1.1", SSDF_1_1),
    KnowledgeChunk("ssdf-1-1-pw1-2", "Security requirements and design", "NIST SSDF", "Document and maintain security requirements, risk information, and security design decisions for the software.", "1.1", "PW.1.2", SSDF_1_1),
    KnowledgeChunk("ssdf-1-1-pw7-2", "Code review and analysis", "NIST SSDF", "Review and analyze code for security issues, then record, triage, and remediate findings.", "1.1", "PW.7.2", SSDF_1_1),
    KnowledgeChunk("ssdf-1-1-pw8-2", "Security testing", "NIST SSDF", "Define the testing scope and approach, execute security tests, and document and triage discovered issues.", "1.1", "PW.8.2", SSDF_1_1),
    KnowledgeChunk("ssdf-1-1-pw9-1", "Secure default settings", "NIST SSDF", "Define and use secure baseline configurations for software and its development environments.", "1.1", "PW.9.1", SSDF_1_1),
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
            ranked.append(RetrievedContext(chunk.source_id, chunk.title, chunk.framework, chunk.content, score, chunk.version, chunk.control_id, chunk.source_url))
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

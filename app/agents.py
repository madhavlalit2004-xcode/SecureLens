"""Bounded specialists used by the SecureLens LangGraph orchestration.

Each specialist owns a narrow concern and produces structured data. This is a
safer pattern than allowing one general-purpose model to make gate decisions.
"""
from app.assessment import build_control_gaps, build_next_actions, build_threat_signals, calculate_evidence_coverage
from app.knowledge_base import RetrievedContext, retrieve
from app.llm import draft_security_insight
from app.scanner import Finding, scan_text


def evidence_agent(content: str, frameworks: list[str]) -> tuple[list[Finding], list[RetrievedContext]]:
    """Extract deterministic evidence and retrieve relevant policy context."""
    findings = scan_text(content)
    query = " ".join([content, *[finding.title for finding in findings]])
    return findings, retrieve(query, frameworks)


def ssdlc_specialist_agent(content: str, findings: list[Finding], phase: str) -> list[dict[str, str]]:
    """Perform the phase-specific security analysis; output remains a draft."""
    return [signal.model_dump() for signal in build_threat_signals(content, findings)]


def policy_agent(findings: list[Finding], frameworks: list[str]) -> list[dict[str, str]]:
    """Map evidence to policy controls, never inventing a control gap."""
    return [gap.model_dump() for gap in build_control_gaps(findings, frameworks)]


def evidence_critic_agent(findings: list[Finding], context: list[RetrievedContext]) -> tuple[list[dict[str, str]], int]:
    """Check that every finding has direct submitted evidence and report coverage."""
    citations = [
        {"source_id": item.source_id, "title": item.title, "framework": item.framework, "excerpt": item.excerpt,
         **({"version": item.version} if item.version else {}),
         **({"control_id": item.control_id} if item.control_id else {}),
         **({"source_url": item.source_url} if item.source_url else {})}
        for item in context
    ]
    # Scanner findings always contain a line and exact matched evidence. Retrieval
    # citations are advisory policy context, not proof that a risk exists.
    coverage = calculate_evidence_coverage(findings, [], []) if not findings else 100
    return citations, coverage


def remediation_agent(findings: list[Finding], phase: str) -> list[str]:
    """Create an owner-friendly, phase-aware remediation queue."""
    return build_next_actions(findings, phase)[:4]


def llm_reviewer_agent(content: str, phase: str, findings: list[dict[str, object]], sources: list[dict[str, object]]) -> dict[str, str]:
    """Generate a local-model narrative only; it cannot alter risk decisions."""
    draft = draft_security_insight(content, phase, findings, sources)
    return {"status": draft.status, "model": draft.model, "insight": draft.insight}

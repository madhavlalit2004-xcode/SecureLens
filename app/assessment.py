"""Domain models and deterministic SSDLC enrichment for SecureLens.

This module intentionally keeps policy decisions deterministic.  An LLM can be
introduced as a drafting/review step without becoming the authority for a gate.
"""
from collections import Counter
from typing import Literal

from pydantic import BaseModel, Field

from app.scanner import Finding

Phase = Literal["requirements", "design", "development", "testing", "deployment", "operations"]


class ControlGap(BaseModel):
    control_id: str
    framework: str
    title: str
    status: Literal["gap", "attention"]
    rationale: str


class ThreatSignal(BaseModel):
    category: str
    title: str
    likelihood: Literal["low", "medium", "high"]
    impact: Literal["low", "medium", "high"]
    evidence: str


class AssessmentRequest(BaseModel):
    content: str = Field(min_length=1, max_length=200_000)
    phase: Phase = "design"
    project_name: str = Field(default="Untitled review", max_length=100)
    frameworks: list[str] = Field(default_factory=lambda: ["OWASP ASVS", "NIST SSDF"])


class AssessmentResponse(BaseModel):
    assessment_id: str
    project_name: str
    phase: Phase
    frameworks: list[str]
    risk_level: str
    analyst_brief: str
    findings: list[Finding]
    compliance_gaps: list[ControlGap]
    threat_signals: list[ThreatSignal]
    next_actions: list[str]
    evidence_coverage: int
    retrieved_context: list[dict[str, str]] = Field(default_factory=list)
    agent_trace: list[str] = Field(default_factory=list)
    ai_review: dict[str, str] = Field(default_factory=dict)


RULE_CONTROL_MAP = {
    "hardcoded-secret": ("V6.4", "OWASP ASVS", "Protect sensitive data and secrets"),
    "private-key-in-content": ("V6.4", "OWASP ASVS", "Protect sensitive data and secrets"),
    "tls-verification-disabled": ("V9.1", "OWASP ASVS", "Secure communications"),
    "insecure-http": ("V9.1", "OWASP ASVS", "Secure communications"),
    "debug-mode-enabled": ("PW.6", "NIST SSDF", "Secure release configuration"),
    "permissive-cors": ("V14.5", "OWASP ASVS", "Validate browser security controls"),
}


def build_control_gaps(findings: list[Finding], frameworks: list[str]) -> list[ControlGap]:
    gaps: list[ControlGap] = []
    permitted = {item.lower() for item in frameworks}
    seen: set[str] = set()
    for finding in findings:
        mapping = RULE_CONTROL_MAP.get(finding.rule_id)
        if not mapping or mapping[0] in seen:
            continue
        control_id, framework, title = mapping
        if framework.lower() in permitted:
            gaps.append(ControlGap(
                control_id=control_id, framework=framework, title=title, status="gap",
                rationale=f"{finding.title} is evidenced on line {finding.line}.",
            ))
            seen.add(control_id)
    return gaps


def build_threat_signals(content: str, findings: list[Finding]) -> list[ThreatSignal]:
    signals: list[ThreatSignal] = []
    lowered = content.lower()
    if any(item.rule_id in {"hardcoded-secret", "private-key-in-content"} for item in findings):
        signals.append(ThreatSignal(category="Information disclosure", title="Credential exposure", likelihood="high", impact="high", evidence="Secret-like material was detected in the submitted evidence."))
    if any(item.rule_id in {"tls-verification-disabled", "insecure-http"} for item in findings):
        signals.append(ThreatSignal(category="Tampering", title="Transport interception", likelihood="medium", impact="high", evidence="The submitted configuration does not enforce a verified encrypted transport."))
    if "admin" in lowered and ("public" in lowered or "internet" in lowered):
        signals.append(ThreatSignal(category="Elevation of privilege", title="Exposed administrative surface", likelihood="medium", impact="high", evidence="Administrative and public/internet-facing terms occur together in the evidence."))
    return signals


def build_next_actions(findings: list[Finding], phase: Phase) -> list[str]:
    actions = list(dict.fromkeys(finding.recommendation for finding in findings))[:3]
    phase_actions = {
        "requirements": "Add acceptance criteria for authentication, authorization, encryption, and audit logging.",
        "design": "Validate the identified threat signals in a human-led STRIDE review before approval.",
        "development": "Open remediation tickets and require secure-code review before merge.",
        "testing": "Add a regression test for each verified finding and record evidence of the result.",
        "deployment": "Block release until high-risk configuration findings have an approved exception or fix.",
        "operations": "Create monitoring coverage and an incident runbook for verified high-risk risks.",
    }
    actions.append(phase_actions[phase])
    return actions[:4]


def calculate_evidence_coverage(findings: list[Finding], gaps: list[ControlGap], threats: list[ThreatSignal]) -> int:
    if not findings:
        return 100
    evidenced = len({finding.rule_id for finding in findings})
    addressed = len(gaps) + len(threats)
    return min(100, round(100 * min(evidenced, addressed) / evidenced))

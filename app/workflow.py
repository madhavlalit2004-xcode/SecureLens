from typing import TypedDict

from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph

from app.scanner import Finding, scan_text
from app.agents import evidence_agent, evidence_critic_agent, llm_reviewer_agent, policy_agent, remediation_agent, ssdlc_specialist_agent


class ReviewState(TypedDict):
    content: str
    findings: list[dict[str, object]]
    risk_level: str
    analyst_brief: str
    phase: str
    frameworks: list[str]
    compliance_gaps: list[dict[str, object]]
    threat_signals: list[dict[str, object]]
    next_actions: list[str]
    evidence_coverage: int
    retrieved_context: list[dict[str, str]]
    agent_trace: list[str]
    ai_review: dict[str, str]


@tool
def detect_security_findings(content: str) -> list[dict[str, object]]:
    """Find deterministic security issues in document or configuration text."""
    return [finding.model_dump() for finding in scan_text(content)]


def scan_document_node(state: ReviewState) -> dict[str, list[dict[str, object]]]:
    findings, context = evidence_agent(state["content"], state["frameworks"])
    sources = [{"source_id": item.source_id, "title": item.title, "framework": item.framework, "excerpt": item.excerpt} for item in context]
    return {"findings": [item.model_dump() for item in findings], "retrieved_context": sources, "agent_trace": ["Evidence Agent: extracted signals and retrieved policy context"]}


def classify_risk_node(state: ReviewState) -> dict[str, str]:
    high_count = sum(
        finding["severity"] == "high" for finding in state["findings"]
    )
    medium_count = sum(
        finding["severity"] == "medium" for finding in state["findings"]
    )

    if high_count >= 2:
        risk_level = "critical"
    elif high_count:
        risk_level = "high"
    elif medium_count:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {"risk_level": risk_level}


def create_review_brief_node(state: ReviewState) -> dict[str, str]:
    findings = state["findings"]

    if not findings:
        brief = (
            "No configured security rules were triggered. "
            "This is not a guarantee that the content is secure."
        )
    else:
        high_count = sum(
            finding["severity"] == "high" for finding in findings
        )
        medium_count = sum(
            finding["severity"] == "medium" for finding in findings
        )
        critical_prefix = "Immediate remediation is recommended. " if state["risk_level"] == "critical" else ""
        brief = (
            f"SecureLens classified this review as {state['risk_level']} risk. "
            f"It found {len(findings)} issue(s): "
            f"{high_count} high severity and {medium_count} medium severity. "
            f"{critical_prefix}Review the evidence and recommendations before using this content."
        )

    return {"analyst_brief": brief}


def map_controls_node(state: ReviewState) -> dict[str, list[dict[str, object]]]:
    findings = [Finding.model_validate(item) for item in state["findings"]]
    return {"compliance_gaps": policy_agent(findings, state["frameworks"]), "agent_trace": [*state["agent_trace"], "Policy Agent: mapped evidence to applicable controls"]}


def model_threats_node(state: ReviewState) -> dict[str, list[dict[str, object]]]:
    findings = [Finding.model_validate(item) for item in state["findings"]]
    return {"threat_signals": ssdlc_specialist_agent(state["content"], findings, state["phase"]), "agent_trace": [*state["agent_trace"], f"{state['phase'].title()} Specialist: created phase-aware threat signals"]}


def recommend_actions_node(state: ReviewState) -> dict[str, object]:
    findings = [Finding.model_validate(item) for item in state["findings"]]
    _, coverage = evidence_critic_agent(findings, [])
    actions = remediation_agent(findings, state["phase"])
    return {"next_actions": actions, "evidence_coverage": coverage, "agent_trace": [*state["agent_trace"], "Evidence Critic: confirmed direct source evidence", "Remediation Agent: prioritized review actions"]}


def local_llm_reviewer_node(state: ReviewState) -> dict[str, object]:
    ai_review = llm_reviewer_agent(state["content"], state["phase"], state["findings"], state["retrieved_context"])
    trace = f"Local LLM Reviewer ({ai_review['model']}): {ai_review['status']}"
    return {"ai_review": ai_review, "agent_trace": [*state["agent_trace"], trace]}


workflow = StateGraph(ReviewState)
workflow.add_node("scan_document", scan_document_node)
workflow.add_node("classify_risk", classify_risk_node)
workflow.add_node("create_review_brief", create_review_brief_node)
workflow.add_node("map_controls", map_controls_node)
workflow.add_node("model_threats", model_threats_node)
workflow.add_node("recommend_actions", recommend_actions_node)
workflow.add_node("local_llm_reviewer", local_llm_reviewer_node)

workflow.add_edge(START, "scan_document")
workflow.add_edge("scan_document", "classify_risk")
workflow.add_edge("classify_risk", "create_review_brief")
workflow.add_edge("create_review_brief", "map_controls")
workflow.add_edge("map_controls", "model_threats")
workflow.add_edge("model_threats", "recommend_actions")
workflow.add_edge("recommend_actions", "local_llm_reviewer")
workflow.add_edge("local_llm_reviewer", END)

review_graph = workflow.compile()


def run_review(content: str, phase: str = "design", frameworks: list[str] | None = None) -> ReviewState:
    return review_graph.invoke(
        {
            "content": content,
            "findings": [],
            "risk_level": "low",
            "analyst_brief": "",
            "phase": phase,
            "frameworks": frameworks or ["OWASP ASVS", "NIST SSDF"],
            "compliance_gaps": [],
            "threat_signals": [],
            "next_actions": [],
            "evidence_coverage": 0,
            "retrieved_context": [],
            "agent_trace": [],
            "ai_review": {},
        }
    )

from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.scanner import Finding, scan_text
from app.workflow import run_review
from app.assessment import AssessmentRequest, AssessmentResponse, ControlGap, ThreatSignal
from app.database import get_assessment, initialize_database, review_assessment, save_assessment, update_remediation
from app.documents import DocumentError, extract_text
from app.knowledge_base import add_document


class HealthResponse(BaseModel):
    status: str
    service: str


class ScanRequest(BaseModel):
    content: str = Field(
        min_length=1,
        max_length=200_000,
        description="Text or configuration content to review.",
    )


class ScanResponse(BaseModel):
    finding_count: int
    findings: list[Finding]

class ReviewResponse(ScanResponse):
    risk_level: str
    analyst_brief: str


class ReviewDecision(BaseModel):
    status: str = Field(pattern="^(approved|rejected)$")
    reviewer_note: str = Field(min_length=1, max_length=2_000)


class RemediationUpdate(BaseModel):
    status: str = Field(pattern="^(open|in_progress|resolved|accepted_risk)$")
    owner: str | None = Field(default=None, max_length=100)


app = FastAPI(
    title="SecureLens API",
    description="A lightweight security review API for documents and configurations.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    initialize_database()


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {
        "message": "SecureLens API is running.",
        "docs": "/docs",
    }


@app.get("/api/health", response_model=HealthResponse, tags=["system"])
def health_check() -> HealthResponse:
    return HealthResponse(status="ok", service="securelens-api")


@app.post("/api/scan", response_model=ScanResponse, tags=["security"])
def scan_document(request: ScanRequest) -> ScanResponse:
    findings = scan_text(request.content)
    return ScanResponse(finding_count=len(findings), findings=findings)

@app.post("/api/review", response_model=ReviewResponse, tags=["agent"])
def review_document(request: ScanRequest) -> ReviewResponse:
    review = run_review(request.content)

    return ReviewResponse(
        finding_count=len(review["findings"]),
        findings=[Finding.model_validate(finding) for finding in review["findings"]],
        risk_level=review["risk_level"],
        analyst_brief=review["analyst_brief"],
    )


def build_assessment(request: AssessmentRequest) -> AssessmentResponse:
    """Run a phase-aware, evidence-backed SSDLC assessment draft.

    Results intentionally remain a draft for human security review.
    """
    review = run_review(request.content, request.phase, request.frameworks)
    assessment = AssessmentResponse(
        assessment_id=f"asl_{uuid4().hex[:12]}", project_name=request.project_name,
        phase=request.phase, frameworks=request.frameworks, risk_level=review["risk_level"],
        analyst_brief=review["analyst_brief"],
        findings=[Finding.model_validate(item) for item in review["findings"]],
        compliance_gaps=[ControlGap.model_validate(item) for item in review["compliance_gaps"]],
        threat_signals=[ThreatSignal.model_validate(item) for item in review["threat_signals"]],
        next_actions=review["next_actions"], evidence_coverage=review["evidence_coverage"],
        retrieved_context=review["retrieved_context"], agent_trace=review["agent_trace"],
        ai_review=review["ai_review"],
    )
    save_assessment(assessment.model_dump())
    return assessment


@app.post("/api/assessments", response_model=AssessmentResponse, tags=["assessments"])
def create_assessment(request: AssessmentRequest) -> AssessmentResponse:
    return build_assessment(request)


@app.post("/api/assessments/upload", response_model=AssessmentResponse, tags=["assessments"])
async def create_uploaded_assessment(
    file: UploadFile = File(...), project_name: str = Form("Untitled review"),
    phase: str = Form("design"), frameworks: str = Form("OWASP ASVS,NIST SSDF"),
) -> AssessmentResponse:
    try:
        content = extract_text(file.filename or "upload.txt", await file.read())
        if not content.strip():
            raise DocumentError("No extractable text was found in this file.")
        return build_assessment(AssessmentRequest(content=content, project_name=project_name, phase=phase, frameworks=[item.strip() for item in frameworks.split(",") if item.strip()]))
    except DocumentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/knowledge/documents", tags=["knowledge"])
async def upload_knowledge_document(file: UploadFile = File(...), framework: str = Form("Organization policy")) -> dict[str, object]:
    try:
        text = extract_text(file.filename or "policy.txt", await file.read())
        if not text.strip():
            raise DocumentError("No extractable text was found in this file.")
        document_id, chunks = add_document(file.filename or "policy.txt", framework, text)
        return {"document_id": document_id, "filename": file.filename, "framework": framework, "chunk_count": chunks}
    except DocumentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/assessments/{assessment_id}", tags=["assessments"])
def read_assessment(assessment_id: str) -> dict[str, object]:
    assessment = get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return assessment


@app.post("/api/assessments/{assessment_id}/review", tags=["review"])
def decide_assessment(assessment_id: str, decision: ReviewDecision) -> dict[str, str]:
    if not review_assessment(assessment_id, decision.status, decision.reviewer_note):
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return {"assessment_id": assessment_id, "status": decision.status}


@app.patch("/api/remediations/{action_id}", tags=["review"])
def update_remediation_action(action_id: int, update: RemediationUpdate) -> dict[str, object]:
    if not update_remediation(action_id, update.status, update.owner):
        raise HTTPException(status_code=404, detail="Remediation action not found.")
    return {"action_id": action_id, "status": update.status, "owner": update.owner}

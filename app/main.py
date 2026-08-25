from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.scanner import Finding, scan_text


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


app = FastAPI(
    title="SecureLens API",
    description="A lightweight security review API for documents and configurations.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
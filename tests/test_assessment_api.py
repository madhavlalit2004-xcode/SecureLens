from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_assessment_returns_phase_aware_security_draft() -> None:
    response = client.post(
        "/api/assessments",
        json={
            "project_name": "Checkout",
            "phase": "design",
            "frameworks": ["OWASP ASVS", "NIST SSDF"],
            "content": 'API_KEY = "example-value"\nverify=False',
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["project_name"] == "Checkout"
    assert body["risk_level"] == "critical"
    assert body["compliance_gaps"]
    assert body["threat_signals"]
    assert body["next_actions"]
    assert body["evidence_coverage"] == 100

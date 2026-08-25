from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_scan_endpoint_returns_findings() -> None:
    response = client.post(
        "/api/scan",
        json={"content": 'password = "example-value"'},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["finding_count"] == 1
    assert body["findings"][0]["rule_id"] == "hardcoded-secret"
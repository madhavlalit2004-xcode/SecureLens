from app.workflow import run_review


def test_review_workflow_classifies_high_risk_content() -> None:
    review = run_review('password = "demo-value"')

    assert review["risk_level"] == "high"
    assert len(review["findings"]) == 1
    assert "1 high severity" in review["analyst_brief"]


def test_review_workflow_handles_safe_content() -> None:
    review = run_review("This is ordinary, non-sensitive text.")

    assert review["risk_level"] == "low"
    assert review["findings"] == []
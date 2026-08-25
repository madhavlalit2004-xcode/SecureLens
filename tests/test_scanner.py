from app.scanner import scan_text


def test_scan_text_finds_a_hardcoded_secret() -> None:
    findings = scan_text('API_KEY = "not-a-real-secret"')

    assert len(findings) == 1
    assert findings[0].rule_id == "hardcoded-secret"
    assert findings[0].severity == "high"


def test_scan_text_ignores_safe_text() -> None:
    findings = scan_text("This document describes a secure application.")

    assert findings == []
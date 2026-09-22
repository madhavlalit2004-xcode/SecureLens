from app.scanner import scan_text


def test_scan_text_finds_a_hardcoded_secret() -> None:
    findings = scan_text('API_KEY = "not-a-real-secret"')

    assert len(findings) == 1
    assert findings[0].rule_id == "hardcoded-secret"
    assert findings[0].severity == "high"


def test_scan_text_ignores_safe_text() -> None:
    findings = scan_text("This document describes a secure application.")

    assert findings == []


def test_scan_text_finds_multiple_rules_in_source_order() -> None:
    findings = scan_text(
        'service_url = "http://example.com"\n'
        "verify=False\n"
        "DEBUG = true"
    )

    assert [finding.rule_id for finding in findings] == [
        "insecure-http",
        "tls-verification-disabled",
        "debug-mode-enabled",
    ]


def test_scan_text_does_not_flag_local_http() -> None:
    assert scan_text('service_url = "http://localhost:8000"') == []

import re

from pydantic import BaseModel


class Finding(BaseModel):
    rule_id: str
    severity: str
    title: str
    line: int
    evidence: str
    recommendation: str


class Rule:
    """A deterministic detection rule used by the local scanner."""

    def __init__(
        self,
        rule_id: str,
        severity: str,
        title: str,
        pattern: str,
        recommendation: str,
    ) -> None:
        self.rule_id = rule_id
        self.severity = severity
        self.title = title
        self.pattern = re.compile(pattern)
        self.recommendation = recommendation


RULES: tuple[Rule, ...] = (
    Rule(
        "hardcoded-secret",
        "high",
        "Possible hardcoded secret",
        r'''(?i)\b(api[_-]?key|password|secret|token)\b\s*[:=]\s*["'][^"'\r\n]{4,}["']''',
        "Move the value to a secret manager or environment variable.",
    ),
    Rule(
        "private-key-in-content",
        "high",
        "Private key material detected",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "Remove the key from this content, rotate it if exposed, and store it in a secret manager.",
    ),
    Rule(
        "tls-verification-disabled",
        "high",
        "TLS verification is disabled",
        r"(?i)\b(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false)\b",
        "Enable certificate verification for HTTPS requests.",
    ),
    Rule(
        "insecure-http",
        "medium",
        "Insecure HTTP URL",
        r'''(?i)\bhttp://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b)[^\s"']+''',
        "Use HTTPS unless this is explicitly a local development service.",
    ),
    Rule(
        "debug-mode-enabled",
        "medium",
        "Debug mode appears enabled",
        r"(?i)\b(?:debug|flask_debug|django_debug)\s*[:=]\s*(?:true|1)\b",
        "Disable debug mode in deployed environments to avoid exposing diagnostic details.",
    ),
    Rule(
        "permissive-cors",
        "medium",
        "Permissive CORS configuration",
        r'''(?i)(?:allow_origins|access-control-allow-origin)\s*[:=]\s*["']?\*["']?''',
        "Restrict allowed origins to the specific trusted applications that need access.",
    ),
)


def scan_text(content: str) -> list[Finding]:
    """Return findings in source order so reports are easy to review."""
    findings: list[Finding] = []

    for rule in RULES:
        for match in rule.pattern.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    line=line,
                    evidence=match.group(0),
                    recommendation=rule.recommendation,
                )
            )

    return sorted(findings, key=lambda finding: (finding.line, finding.rule_id))

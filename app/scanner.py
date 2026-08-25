import re

from pydantic import BaseModel


class Finding(BaseModel):
    rule_id: str
    severity: str
    title: str
    line: int
    evidence: str
    recommendation: str


RULES = (
    {
        "rule_id": "hardcoded-secret",
        "severity": "high",
        "title": "Possible hardcoded secret",
        "pattern": re.compile(
            r"""(?i)\b(api[_-]?key|password|secret|token)\b\s*[:=]\s*["'][^"']+["']"""
        ),
        "recommendation": "Move the value to a secret manager or environment variable.",
    },
    {
        "rule_id": "insecure-http",
        "severity": "medium",
        "title": "Insecure HTTP URL",
        "pattern": re.compile(r"""(?i)\bhttp://[^\s"']+"""),
        "recommendation": "Use HTTPS unless this is explicitly a local development service.",
    },
    {
        "rule_id": "tls-verification-disabled",
        "severity": "high",
        "title": "TLS verification is disabled",
        "pattern": re.compile(r"""(?i)\bverify\s*=\s*False\b"""),
        "recommendation": "Enable certificate verification for HTTPS requests.",
    },
)


def scan_text(content: str) -> list[Finding]:
    findings: list[Finding] = []

    for rule in RULES:
        for match in rule["pattern"].finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    rule_id=rule["rule_id"],
                    severity=rule["severity"],
                    title=rule["title"],
                    line=line,
                    evidence=match.group(0),
                    recommendation=rule["recommendation"],
                )
            )

    return findings
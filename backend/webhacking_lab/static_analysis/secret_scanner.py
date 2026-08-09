"""Conservative secret-shape detection and presentation-time redaction."""

import re

from webhacking_lab.static_analysis.models import SecretFinding

REDACTION = "<redacted-secret>"
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "assigned_secret",
        re.compile(
            r"(?im)(?P<prefix>\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*[\"']?)"
            r"(?P<value>[A-Za-z0-9_./+=-]{8,})(?P<suffix>[\"']?)"
        ),
    ),
)


def find_secrets(content: str) -> list[SecretFinding]:
    """Return kind and line only, never the matched secret value."""

    findings: list[SecretFinding] = []
    for kind, pattern in PATTERNS:
        findings.extend(
            SecretFinding(
                kind=kind,
                line=content.count("\n", 0, match.start()) + 1,
            )
            for match in pattern.finditer(content)
        )
    return findings


def redact_source(content: str) -> tuple[str, bool]:
    """Mask recognized secrets while preserving surrounding source context."""

    redacted = False
    rendered = content
    for kind, pattern in PATTERNS:
        if kind == "assigned_secret":
            rendered, count = pattern.subn(
                lambda match: f"{match.group('prefix')}{REDACTION}{match.group('suffix')}",
                rendered,
            )
        else:
            rendered, count = pattern.subn(REDACTION, rendered)
        redacted = redacted or count > 0
    return rendered, redacted

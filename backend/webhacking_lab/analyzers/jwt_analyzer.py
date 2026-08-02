"""Structure-only JWT observations without forging or cracking tokens."""

import base64
import json
import re
from typing import Any

from webhacking_lab.analyzers.models import (
    AnalysisContext,
    AnalysisResult,
    Evidence,
    Hypothesis,
    Reference,
)
from webhacking_lab.domain.enums import Severity, VerificationStatus, VulnerabilityCategory
from webhacking_lab.http_client.models import NormalizedRequest, NormalizedResponse

JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])"
)


def _decode_segment(value: str) -> dict[str, Any] | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        parsed = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


class JwtStructureAnalyzer:
    """Decode public JWT structure and report configuration signals only."""

    name = "jwt-structure-analyzer"
    category = VulnerabilityCategory.JWT

    async def analyze(
        self,
        request: NormalizedRequest,
        response: NormalizedResponse | None,
        context: AnalysisContext,
    ) -> AnalysisResult:
        del context
        searchable = [item.value for item in request.query if not item.redacted]
        searchable.append(request.body)
        if response is not None:
            searchable.append(response.body)
        token = next(
            (match.group(1) for value in searchable for match in JWT_PATTERN.finditer(value)),
            None,
        )
        header: dict[str, Any] | None = None
        payload: dict[str, Any] | None = None
        if token:
            sections = token.split(".")
            header = _decode_segment(sections[0])
            payload = _decode_segment(sections[1])
        if header is None or payload is None:
            return AnalysisResult(
                analyzer=self.name,
                category=self.category,
                title="JWT structure not observed",
                summary="No decodable three-segment JWT was found in non-secret captured data.",
                evidence=[],
                hypotheses=[],
                safe_test_cases=[],
                confidence=0.6,
                severity=Severity.INFO,
                status=VerificationStatus.NOT_TESTED,
                remediation=[],
                references=[],
                limitations=["Authorization and cookie values are redacted before persistence."],
            )
        algorithm = str(header.get("alg", "missing"))
        missing_expiration = "exp" not in payload
        risky_algorithm = algorithm.lower() == "none"
        suspicious = risky_algorithm or missing_expiration
        evidence = [
            Evidence(title="Declared algorithm", detail=algorithm, location="JWT header"),
            Evidence(
                title="Expiration claim",
                detail="missing" if missing_expiration else "present",
                location="JWT payload",
            ),
        ]
        return AnalysisResult(
            analyzer=self.name,
            category=self.category,
            title="JWT structure observation",
            summary="The public header and claim names were decoded; the signature was not tested.",
            evidence=evidence,
            hypotheses=[
                Hypothesis(
                    title="JWT validation policy may need review",
                    rationale=(
                        "Declared algorithm or lifetime claims require server-side validation."
                    ),
                    status=VerificationStatus.SUSPICIOUS,
                )
            ]
            if suspicious
            else [],
            safe_test_cases=[],
            confidence=0.85,
            severity=Severity.HIGH
            if risky_algorithm
            else Severity.LOW
            if suspicious
            else Severity.INFO,
            status=(
                VerificationStatus.SUSPICIOUS if suspicious else VerificationStatus.OBSERVATION
            ),
            remediation=[
                "Pin allowed algorithms server-side and reject unsecured tokens.",
                "Validate issuer, audience, expiry, and not-before claims for the use case.",
            ],
            references=[
                Reference(
                    title="OWASP JWT Cheat Sheet",
                    url="https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                )
            ],
            limitations=[
                "Structure decoding does not validate the signature or prove token acceptance.",
                "No token mutation, key guessing, or signature bypass is attempted.",
            ],
        )

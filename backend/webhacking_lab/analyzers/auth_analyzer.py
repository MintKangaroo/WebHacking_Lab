"""Passive cookie and authentication transport observations."""

from webhacking_lab.analyzers.common import header_values
from webhacking_lab.analyzers.models import (
    AnalysisContext,
    AnalysisResult,
    Evidence,
    Hypothesis,
    Reference,
)
from webhacking_lab.domain.enums import Severity, VerificationStatus, VulnerabilityCategory
from webhacking_lab.http_client.models import NormalizedRequest, NormalizedResponse


class AuthenticationAnalyzer:
    """Inspect captured Set-Cookie attributes without handling credentials."""

    name = "authentication-analyzer"
    category = VulnerabilityCategory.AUTHENTICATION

    async def analyze(
        self,
        request: NormalizedRequest,
        response: NormalizedResponse | None,
        context: AnalysisContext,
    ) -> AnalysisResult:
        del request, context
        cookies = header_values(response.headers, "set-cookie") if response else []
        issues: list[str] = []
        for cookie in cookies:
            lowered = cookie.lower()
            if "secure" not in lowered:
                issues.append("Secure attribute was not observed")
            if "httponly" not in lowered:
                issues.append("HttpOnly attribute was not observed")
            if "samesite" not in lowered:
                issues.append("SameSite attribute was not observed")
        unique_issues = list(dict.fromkeys(issues))
        status = (
            VerificationStatus.OBSERVATION
            if unique_issues
            else (VerificationStatus.FALSE_POSITIVE if response else VerificationStatus.NOT_TESTED)
        )
        return AnalysisResult(
            analyzer=self.name,
            category=self.category,
            title="Session cookie attributes",
            summary=(
                f"{len(unique_issues)} cookie hardening observations were identified."
                if unique_issues
                else "No cookie attribute weakness was observed in this response."
            ),
            evidence=[
                Evidence(title="Cookie attribute observation", detail=issue, location="Set-Cookie")
                for issue in unique_issues
            ],
            hypotheses=[
                Hypothesis(
                    title="Session cookie hardening may be incomplete",
                    rationale="Cookie purpose and deployment scheme must be confirmed manually.",
                    status=VerificationStatus.OBSERVATION,
                )
            ]
            if unique_issues
            else [],
            safe_test_cases=[],
            confidence=0.85 if cookies else 0.4 if response else 0,
            severity=Severity.LOW if unique_issues else Severity.INFO,
            status=status,
            remediation=[
                "Set Secure and HttpOnly for session cookies.",
                "Choose the narrowest SameSite policy compatible with the application flow.",
            ]
            if unique_issues
            else [],
            references=[
                Reference(
                    title="OWASP Session Management Cheat Sheet",
                    url="https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                )
            ],
            limitations=["Redacted cookie values prevent session identity or entropy analysis."],
        )

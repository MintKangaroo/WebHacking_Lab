"""Passive browser security-header analysis."""

from webhacking_lab.analyzers.common import first_header
from webhacking_lab.analyzers.models import (
    AnalysisContext,
    AnalysisResult,
    Evidence,
    Hypothesis,
    Reference,
)
from webhacking_lab.domain.enums import Severity, VerificationStatus, VulnerabilityCategory
from webhacking_lab.http_client.models import NormalizedRequest, NormalizedResponse

EXPECTED_HEADERS = {
    "content-security-policy": "Reduce script injection impact with a context-appropriate CSP.",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
    "referrer-policy": "Set a restrictive Referrer-Policy.",
    "permissions-policy": "Disable browser capabilities that are not required.",
}


class SecurityHeaderAnalyzer:
    """Report missing controls as observations, never confirmed vulnerabilities."""

    name = "security-header-analyzer"
    category = VulnerabilityCategory.SECURITY_HEADERS

    async def analyze(
        self,
        request: NormalizedRequest,
        response: NormalizedResponse | None,
        context: AnalysisContext,
    ) -> AnalysisResult:
        del request, context
        if response is None:
            return AnalysisResult(
                analyzer=self.name,
                category=self.category,
                title="Security header review not tested",
                summary="A response is required to inspect browser security controls.",
                evidence=[],
                hypotheses=[],
                safe_test_cases=[],
                confidence=0,
                severity=Severity.INFO,
                status=VerificationStatus.NOT_TESTED,
                remediation=[],
                references=[],
                limitations=["No response was supplied."],
            )
        missing = [
            name for name in EXPECTED_HEADERS if first_header(response.headers, name) is None
        ]
        evidence = [
            Evidence(
                title="Header absent",
                detail=f"{name} was not present in the captured response.",
                location="response.headers",
            )
            for name in missing
        ]
        return AnalysisResult(
            analyzer=self.name,
            category=self.category,
            title="Browser security header posture",
            summary=(
                f"{len(missing)} recommended headers were not observed."
                if missing
                else "The baseline recommended headers were present."
            ),
            evidence=evidence,
            hypotheses=[
                Hypothesis(
                    title="Browser defense-in-depth may be incomplete",
                    rationale=(
                        "Missing headers can increase impact but do not prove exploitability."
                    ),
                    status=VerificationStatus.OBSERVATION,
                )
            ]
            if missing
            else [],
            safe_test_cases=[],
            confidence=0.95,
            severity=Severity.LOW if missing else Severity.INFO,
            status=(
                VerificationStatus.OBSERVATION if missing else VerificationStatus.FALSE_POSITIVE
            ),
            remediation=[EXPECTED_HEADERS[name] for name in missing],
            references=[
                Reference(
                    title="OWASP Secure Headers Project",
                    url="https://owasp.org/www-project-secure-headers/",
                )
            ],
            limitations=["Header requirements vary by content type and application behavior."],
        )

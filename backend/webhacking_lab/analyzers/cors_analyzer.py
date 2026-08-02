"""Passive CORS policy analysis."""

from webhacking_lab.analyzers.common import first_header
from webhacking_lab.analyzers.models import (
    AnalysisContext,
    AnalysisResult,
    Evidence,
    Hypothesis,
    Reference,
    TestCase,
)
from webhacking_lab.domain.enums import (
    RiskLevel,
    Severity,
    VerificationStatus,
    VulnerabilityCategory,
)
from webhacking_lab.http_client.models import NormalizedRequest, NormalizedResponse


class CorsAnalyzer:
    """Flag risky captured CORS combinations without sending Origin probes."""

    name = "cors-analyzer"
    category = VulnerabilityCategory.CORS

    async def analyze(
        self,
        request: NormalizedRequest,
        response: NormalizedResponse | None,
        context: AnalysisContext,
    ) -> AnalysisResult:
        del request, context
        origin = first_header(response.headers, "access-control-allow-origin") if response else None
        credentials = (
            first_header(response.headers, "access-control-allow-credentials") if response else None
        )
        if response is None or origin is None:
            return AnalysisResult(
                analyzer=self.name,
                category=self.category,
                title="CORS policy not observed",
                summary="The captured response did not expose a CORS allow-origin policy.",
                evidence=[],
                hypotheses=[],
                safe_test_cases=[],
                confidence=0.8 if response else 0,
                severity=Severity.INFO,
                status=(
                    VerificationStatus.FALSE_POSITIVE if response else VerificationStatus.NOT_TESTED
                ),
                remediation=[],
                references=[],
                limitations=["Only the captured Origin context can be evaluated passively."],
            )
        risky = origin == "*" and (credentials or "").lower() == "true"
        wildcard = origin == "*"
        return AnalysisResult(
            analyzer=self.name,
            category=self.category,
            title="CORS policy observation",
            summary=(
                "Wildcard origin and credential signals were observed together."
                if risky
                else f"The captured response allows origin {origin}."
            ),
            evidence=[
                Evidence(
                    title="Allow-Origin value",
                    detail=origin,
                    location="response.headers.access-control-allow-origin",
                ),
                Evidence(
                    title="Allow-Credentials value",
                    detail=credentials or "not present",
                    location="response.headers.access-control-allow-credentials",
                ),
            ],
            hypotheses=[
                Hypothesis(
                    title="Cross-origin policy may be broader than intended",
                    rationale=(
                        "Runtime Origin reflection and sensitive response access need validation."
                    ),
                    status=VerificationStatus.SUSPICIOUS
                    if risky
                    else VerificationStatus.OBSERVATION,
                )
            ],
            safe_test_cases=[
                TestCase(
                    title="Single untrusted Origin comparison",
                    objective="Compare allow-origin behavior using a non-routable example origin.",
                    parameter="Origin",
                    mutation_type="header_replace",
                    preview_value="https://origin.invalid",
                    expected_signal=["Origin reflection", "credentialed response policy"],
                    risk_level=RiskLevel.LOW,
                )
            ],
            confidence=0.9 if risky else 0.65,
            severity=Severity.MEDIUM if risky else Severity.INFO,
            status=(
                VerificationStatus.SUSPICIOUS
                if risky or wildcard
                else VerificationStatus.OBSERVATION
            ),
            remediation=[
                "Allow only exact trusted origins and vary cache entries on Origin.",
                "Do not combine broadly trusted origins with credentialed responses.",
            ],
            references=[
                Reference(
                    title="OWASP CORS guidance",
                    url="https://cheatsheetseries.owasp.org/cheatsheets/CORS_Configuration_Cheat_Sheet.html",
                )
            ],
            limitations=["A captured header alone does not prove cross-origin data exposure."],
        )

"""Passive reflected-input context analysis."""

import html

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


class XssReflectionAnalyzer:
    """Find non-secret input reflections but avoid executable payload generation."""

    name = "xss-reflection-analyzer"
    category = VulnerabilityCategory.XSS

    async def analyze(
        self,
        request: NormalizedRequest,
        response: NormalizedResponse | None,
        context: AnalysisContext,
    ) -> AnalysisResult:
        del context
        body = response.body if response else ""
        reflected = [
            item
            for item in request.query
            if not item.redacted
            and len(item.value) >= 3
            and item.value in body
            and html.escape(item.value) == item.value
        ]
        return AnalysisResult(
            analyzer=self.name,
            category=self.category,
            title="Reflected input context",
            summary=(
                f"{len(reflected)} query value(s) were reflected verbatim in the response."
                if reflected
                else "No plain query reflection was observed in the captured response."
            ),
            evidence=[
                Evidence(
                    title="Verbatim query reflection",
                    detail=f"Parameter {item.name} was reflected without visible encoding changes.",
                    location="response.body",
                )
                for item in reflected
            ],
            hypotheses=[
                Hypothesis(
                    title="Output context may require encoding review",
                    rationale=(
                        "Reflection is necessary for some XSS paths but is not sufficient proof."
                    ),
                    status=VerificationStatus.SUSPICIOUS,
                )
            ]
            if reflected
            else [],
            safe_test_cases=[
                TestCase(
                    title="Non-executable reflection marker",
                    objective="Locate the output context using a unique inert marker.",
                    parameter=reflected[0].name,
                    mutation_type="query_replace",
                    preview_value="WHL_REFLECTION_7F3A",
                    expected_signal=["marker reflection", "HTML encoding transformation"],
                    risk_level=RiskLevel.LOW,
                )
            ]
            if reflected
            else [],
            confidence=0.7 if reflected else 0.55,
            severity=Severity.MEDIUM if reflected else Severity.INFO,
            status=(
                VerificationStatus.SUSPICIOUS if reflected else VerificationStatus.FALSE_POSITIVE
            ),
            remediation=[
                "Apply output encoding for the exact HTML, attribute, URL, or script context.",
                "Prefer templating APIs with automatic contextual escaping.",
            ]
            if reflected
            else [],
            references=[
                Reference(
                    title="OWASP XSS Prevention Cheat Sheet",
                    url="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                )
            ],
            limitations=["Passive reflection cannot confirm script execution or browser context."],
        )

"""Inert reflection marker plugin; it never sends executable markup."""

from typing import ClassVar

from webhacking_lab.analyzers.models import AnalysisResult, Evidence, TestCase
from webhacking_lab.domain.enums import (
    RiskLevel,
    ScannerProfile,
    Severity,
    VerificationStatus,
    VulnerabilityCategory,
)
from webhacking_lab.scanner.models import ActiveEndpoint, HttpExchange, ScanContext
from webhacking_lab.scanner.plugins.helpers import result

MARKER = "WHL_REFLECTION_PROBE_7F3A"


class ReflectedXssPlugin:
    plugin_id = "safe-reflected-xss"
    category = VulnerabilityCategory.XSS
    supported_profiles = frozenset({ScannerProfile.SAFE})
    success_criteria = "The inert marker is returned in an HTML response."
    false_positive_notes = "Reflection alone does not establish an executable browser context."
    remediation: ClassVar[list[str]] = [
        "Contextually encode untrusted output and enforce a restrictive CSP."
    ]

    async def create_test_plan(
        self, endpoint: ActiveEndpoint, context: ScanContext
    ) -> list[TestCase]:
        del context
        parameter = next((item for item in endpoint.parameters if item.location == "query"), None)
        return (
            []
            if parameter is None
            else [
                TestCase(
                    title="Inert HTML reflection marker",
                    objective="Check reflection without sending tags, scripts, or event handlers.",
                    parameter=parameter.name,
                    mutation_type="xss_inert_marker",
                    preview_value=MARKER,
                    expected_signal=["exact inert marker in an HTML response"],
                    risk_level=RiskLevel.INFO,
                )
            ]
        )

    async def evaluate(
        self, baseline: HttpExchange, test_exchanges: list[HttpExchange], context: ScanContext
    ) -> AnalysisResult:
        del baseline, context
        reflected = next(
            (
                item
                for item in test_exchanges
                if MARKER in item.body
                and any(
                    name.lower() == "content-type" and "html" in value.lower()
                    for name, value in item.headers
                )
            ),
            None,
        )
        if reflected is not None:
            return result(
                analyzer=self.plugin_id,
                category=self.category,
                title="Runtime reflection candidate",
                summary=(
                    "An inert marker was reflected in HTML; executable context remains untested."
                ),
                status=VerificationStatus.LIKELY,
                confidence=0.78,
                severity=Severity.MEDIUM,
                evidence=[
                    Evidence(
                        title="Inert marker reflected", detail=MARKER, location="response.body"
                    )
                ],
                remediation=self.remediation,
                limitations=[self.false_positive_notes],
            )
        return result(
            analyzer=self.plugin_id,
            category=self.category,
            title="No reflection observed",
            summary="The approved inert marker was not reflected in an HTML response.",
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.7,
            severity=Severity.INFO,
            evidence=[],
            remediation=self.remediation,
            limitations=["Encoding or alternate rendering paths may require manual review."],
        )

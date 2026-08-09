"""Reserved-domain open redirect observation plugin."""

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

REDIRECT_MARKER = "https://example.invalid/whl-safe-redirect"


class OpenRedirectPlugin:
    plugin_id = "safe-open-redirect"
    category = VulnerabilityCategory.OPEN_REDIRECT
    supported_profiles = frozenset({ScannerProfile.SAFE})
    success_criteria = "A 3xx response sets Location to the reserved example.invalid marker."
    false_positive_notes = (
        "Some applications deliberately allow redirects through trusted interstitials."
    )
    remediation: ClassVar[list[str]] = [
        "Resolve redirects to server-side route identifiers or an explicit destination allowlist."
    ]

    async def create_test_plan(
        self, endpoint: ActiveEndpoint, context: ScanContext
    ) -> list[TestCase]:
        del context
        names = {"next", "url", "redirect", "redirect_uri", "return", "return_to", "continue"}
        parameter = next(
            (
                item
                for item in endpoint.parameters
                if item.location == "query" and item.name.lower() in names
            ),
            None,
        )
        return (
            []
            if parameter is None
            else [
                TestCase(
                    title="Reserved-domain redirect observation",
                    objective="Observe one response Location without following the redirect.",
                    parameter=parameter.name,
                    mutation_type="open_redirect_reserved_domain",
                    preview_value=REDIRECT_MARKER,
                    expected_signal=["3xx Location points to example.invalid"],
                    risk_level=RiskLevel.LOW,
                )
            ]
        )

    async def evaluate(
        self, baseline: HttpExchange, test_exchanges: list[HttpExchange], context: ScanContext
    ) -> AnalysisResult:
        del baseline, context
        signal = next(
            (
                (item, value)
                for item in test_exchanges
                for name, value in item.headers
                if name.lower() == "location" and value.startswith(REDIRECT_MARKER)
            ),
            None,
        )
        if signal is not None:
            return result(
                analyzer=self.plugin_id,
                category=self.category,
                title="Open redirect behavior confirmed",
                summary=(
                    "The application returned the reserved external destination without the "
                    "scanner following it."
                ),
                status=VerificationStatus.CONFIRMED,
                confidence=0.95,
                severity=Severity.MEDIUM,
                evidence=[
                    Evidence(title="Location header", detail=signal[1], location="response.headers")
                ],
                remediation=self.remediation,
                limitations=[
                    "Business intent and trusted interstitial behavior still require review."
                ],
            )
        return result(
            analyzer=self.plugin_id,
            category=self.category,
            title="No open redirect signal",
            summary="No response redirected to the reserved external marker.",
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.74,
            severity=Severity.INFO,
            evidence=[],
            remediation=self.remediation,
            limitations=["Only the selected parameter and one destination were evaluated."],
        )

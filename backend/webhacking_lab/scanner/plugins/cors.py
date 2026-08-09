"""Single preflight-style CORS policy observation plugin."""

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

ORIGIN = "https://example.invalid"


class CorsProbePlugin:
    plugin_id = "safe-cors-probe"
    category = VulnerabilityCategory.CORS
    supported_profiles = frozenset({ScannerProfile.SAFE})
    success_criteria = (
        "The response trusts the reserved external Origin, especially with credentials."
    )
    false_positive_notes = "Public unauthenticated resources can intentionally allow broad CORS."
    remediation: ClassVar[list[str]] = [
        "Return Access-Control-Allow-Origin only for explicit trusted origins."
    ]

    async def create_test_plan(
        self, endpoint: ActiveEndpoint, context: ScanContext
    ) -> list[TestCase]:
        del context
        return [
            TestCase(
                title="Reserved-origin CORS observation",
                objective="Send one OPTIONS request with a non-routable reserved Origin.",
                mutation_type="cors_reserved_origin",
                preview_value=ORIGIN,
                expected_signal=[
                    "Access-Control-Allow-Origin reflects reserved Origin",
                    "credentials allowed",
                ],
                risk_level=RiskLevel.INFO,
            )
        ]

    async def evaluate(
        self, baseline: HttpExchange, test_exchanges: list[HttpExchange], context: ScanContext
    ) -> AnalysisResult:
        del baseline, context
        for exchange in test_exchanges:
            headers = {name.lower(): value for name, value in exchange.headers}
            if headers.get("access-control-allow-origin") in {ORIGIN, "*"}:
                credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
                return result(
                    analyzer=self.plugin_id,
                    category=self.category,
                    title="Permissive runtime CORS signal",
                    summary="The endpoint accepted a reserved external Origin."
                    + (" Credentials were also allowed." if credentials else ""),
                    status=VerificationStatus.LIKELY,
                    confidence=0.87 if credentials else 0.72,
                    severity=Severity.HIGH if credentials else Severity.LOW,
                    evidence=[
                        Evidence(
                            title="Access-Control-Allow-Origin",
                            detail=headers["access-control-allow-origin"],
                            location="response.headers",
                        )
                    ],
                    remediation=self.remediation,
                    limitations=[self.false_positive_notes],
                )
        return result(
            analyzer=self.plugin_id,
            category=self.category,
            title="No permissive CORS signal",
            summary="The reserved Origin was not allowed by the approved response.",
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.75,
            severity=Severity.INFO,
            evidence=[],
            remediation=self.remediation,
            limitations=["CORS policy may vary by path, method, or authentication state."],
        )

"""Passive-only plugin adapter included in the active plugin contract."""

from typing import ClassVar

from webhacking_lab.analyzers.models import AnalysisResult, TestCase
from webhacking_lab.domain.enums import (
    ScannerProfile,
    Severity,
    VerificationStatus,
    VulnerabilityCategory,
)
from webhacking_lab.scanner.models import ActiveEndpoint, HttpExchange, ScanContext
from webhacking_lab.scanner.plugins.helpers import result


class SecurityHeaderPlugin:
    plugin_id = "safe-security-headers"
    category = VulnerabilityCategory.SECURITY_HEADERS
    supported_profiles = frozenset({ScannerProfile.SAFE})
    success_criteria = "No mutation request is necessary; baseline headers are evaluated passively."
    false_positive_notes = "Header requirements vary by content and deployment architecture."
    remediation: ClassVar[list[str]] = [
        "Define security headers centrally and verify them at the public edge."
    ]

    async def create_test_plan(
        self, endpoint: ActiveEndpoint, context: ScanContext
    ) -> list[TestCase]:
        del endpoint, context
        return []

    async def evaluate(
        self, baseline: HttpExchange, test_exchanges: list[HttpExchange], context: ScanContext
    ) -> AnalysisResult:
        del baseline, test_exchanges, context
        return result(
            analyzer=self.plugin_id,
            category=self.category,
            title="Security headers evaluated passively",
            summary="No active request was required.",
            status=VerificationStatus.NOT_TESTED,
            confidence=1,
            severity=Severity.INFO,
            evidence=[],
            remediation=self.remediation,
            limitations=[self.false_positive_notes],
        )

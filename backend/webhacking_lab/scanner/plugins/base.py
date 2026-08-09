"""Transport-independent contract for SAFE active scanner plugins."""

from typing import Protocol

from webhacking_lab.analyzers.models import AnalysisResult, TestCase
from webhacking_lab.domain.enums import ScannerProfile, VulnerabilityCategory
from webhacking_lab.scanner.models import ActiveEndpoint, HttpExchange, ScanContext


class ActiveScannerPlugin(Protocol):
    """Generate previews and evaluate only already-captured redacted exchanges."""

    plugin_id: str
    category: VulnerabilityCategory
    supported_profiles: frozenset[ScannerProfile]
    success_criteria: str
    false_positive_notes: str
    remediation: list[str]

    async def create_test_plan(
        self,
        endpoint: ActiveEndpoint,
        context: ScanContext,
    ) -> list[TestCase]:
        """Return bounded test previews without sending a network request."""

    async def evaluate(
        self,
        baseline: HttpExchange,
        test_exchanges: list[HttpExchange],
        context: ScanContext,
    ) -> AnalysisResult:
        """Evaluate redacted evidence without performing more requests."""

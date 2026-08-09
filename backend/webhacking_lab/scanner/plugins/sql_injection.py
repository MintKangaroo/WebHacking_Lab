"""Minimal SQL error and true/false comparison plugin; never extracts data."""

from typing import ClassVar

from webhacking_lab.analyzers.diff_analyzer import DiffAnalyzer
from webhacking_lab.analyzers.injection_analyzer import DBMS_ERRORS
from webhacking_lab.analyzers.models import AnalysisResult, Evidence, TestCase
from webhacking_lab.domain.enums import (
    RiskLevel,
    ScannerProfile,
    Severity,
    VerificationStatus,
    VulnerabilityCategory,
)
from webhacking_lab.http_client.models import NameValue, NormalizedResponse
from webhacking_lab.scanner.models import ActiveEndpoint, HttpExchange, ScanContext
from webhacking_lab.scanner.plugins.helpers import result


def _response(exchange: HttpExchange) -> NormalizedResponse:
    return NormalizedResponse(
        status_code=exchange.status_code,
        headers=[NameValue(name=name, value=value) for name, value in exchange.headers],
        body=exchange.body,
        elapsed_ms=exchange.elapsed_ms,
    )


class SqlInjectionPlugin:
    """Observe one quote and a numeric boolean pair with strict request ceilings."""

    plugin_id = "safe-sql-injection"
    category = VulnerabilityCategory.SQL_INJECTION
    supported_profiles = frozenset({ScannerProfile.SAFE})
    success_criteria = (
        "A new DBMS error signature, or a true response matching baseline while the false "
        "response differs materially."
    )
    false_positive_notes = (
        "Validation errors, caching, authorization, and dynamic pages can differ."
    )
    remediation: ClassVar[list[str]] = [
        "Use parameterized queries and typed bindings for every untrusted value.",
        "Do not expose database error details in HTTP responses.",
    ]

    async def create_test_plan(
        self, endpoint: ActiveEndpoint, context: ScanContext
    ) -> list[TestCase]:
        del context
        parameter = next((item for item in endpoint.parameters if item.location == "query"), None)
        if parameter is None:
            return []
        plans = [
            TestCase(
                title="SQL syntax difference",
                objective="Observe whether one unmatched quote introduces a new DBMS error.",
                parameter=parameter.name,
                mutation_type="sql_quote_append",
                preview_value=f"{parameter.sample_value}'",
                expected_signal=["new DBMS error", "status or normalized body difference"],
                risk_level=RiskLevel.LOW,
            )
        ]
        if parameter.sample_value.isdecimal():
            plans.extend(
                [
                    TestCase(
                        title="SQL boolean true comparison",
                        objective="Compare a read-only true condition with the baseline.",
                        parameter=parameter.name,
                        mutation_type="sql_boolean_true",
                        preview_value=f"{parameter.sample_value} AND 1=1",
                        expected_signal=["response remains similar to baseline"],
                        risk_level=RiskLevel.LOW,
                    ),
                    TestCase(
                        title="SQL boolean false comparison",
                        objective="Compare a read-only false condition with the baseline.",
                        parameter=parameter.name,
                        mutation_type="sql_boolean_false",
                        preview_value=f"{parameter.sample_value} AND 1=2",
                        expected_signal=["normalized response differs from baseline"],
                        risk_level=RiskLevel.LOW,
                    ),
                ]
            )
        return plans

    async def evaluate(
        self, baseline: HttpExchange, test_exchanges: list[HttpExchange], context: ScanContext
    ) -> AnalysisResult:
        del context
        baseline_errors = {
            name for name, pattern in DBMS_ERRORS.items() if pattern.search(baseline.body)
        }
        for exchange in test_exchanges:
            errors = {
                name for name, pattern in DBMS_ERRORS.items() if pattern.search(exchange.body)
            }
            added = sorted(errors - baseline_errors)
            if added:
                return result(
                    analyzer=self.plugin_id,
                    category=self.category,
                    title="Runtime SQL error signal",
                    summary=f"A controlled quote introduced a {', '.join(added)} error signature.",
                    status=VerificationStatus.CONFIRMED,
                    confidence=0.93,
                    severity=Severity.HIGH,
                    evidence=[
                        Evidence(title="New DBMS error", detail=name, location="response.body")
                        for name in added
                    ],
                    remediation=self.remediation,
                    limitations=[
                        "This confirms an error signal, not readable data or impact beyond "
                        "the tested input."
                    ],
                )
        true_exchange = next(
            (item for item in test_exchanges if item.mutation_type == "sql_boolean_true"), None
        )
        false_exchange = next(
            (item for item in test_exchanges if item.mutation_type == "sql_boolean_false"), None
        )
        if true_exchange is not None and false_exchange is not None:
            comparator = DiffAnalyzer()
            true_diff = comparator.compare(_response(baseline), _response(true_exchange))
            false_diff = comparator.compare(_response(baseline), _response(false_exchange))
            if true_diff.body_similarity >= 0.96 and false_diff.body_similarity <= 0.85:
                return result(
                    analyzer=self.plugin_id,
                    category=self.category,
                    title="Probable runtime SQL boolean signal",
                    summary=(
                        "The true condition matched baseline while the false condition differed."
                    ),
                    status=VerificationStatus.LIKELY,
                    confidence=0.84,
                    severity=Severity.HIGH,
                    evidence=[
                        Evidence(
                            title="True similarity", detail=f"{true_diff.body_similarity:.3f}"
                        ),
                        Evidence(
                            title="False similarity", detail=f"{false_diff.body_similarity:.3f}"
                        ),
                    ],
                    remediation=self.remediation,
                    limitations=[
                        "One true/false pair is probable evidence; repeat manually before "
                        "confirmation."
                    ],
                )
        return result(
            analyzer=self.plugin_id,
            category=self.category,
            title="No reliable SQL injection signal",
            summary=(
                "Approved comparison requests did not produce a reliable SQL error or "
                "boolean signal."
            ),
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.72,
            severity=Severity.INFO,
            evidence=[],
            remediation=self.remediation,
            limitations=["A negative bounded test does not prove that every context is safe."],
        )

"""Small shared builders for conservative active plugin results."""

from webhacking_lab.analyzers.models import AnalysisResult, Evidence, Hypothesis, Reference
from webhacking_lab.domain.enums import Severity, VerificationStatus, VulnerabilityCategory


def result(
    *,
    analyzer: str,
    category: VulnerabilityCategory,
    title: str,
    summary: str,
    status: VerificationStatus,
    confidence: float,
    severity: Severity,
    evidence: list[Evidence],
    remediation: list[str],
    limitations: list[str],
) -> AnalysisResult:
    """Build a result that keeps runtime signals separate from confirmation."""

    return AnalysisResult(
        analyzer=analyzer,
        category=category,
        title=title,
        summary=summary,
        evidence=evidence,
        hypotheses=[
            Hypothesis(
                title=title,
                rationale=summary,
                status=status,
            )
        ]
        if status not in {VerificationStatus.FALSE_POSITIVE, VerificationStatus.NOT_TESTED}
        else [],
        safe_test_cases=[],
        confidence=confidence,
        severity=severity,
        status=status,
        remediation=remediation,
        references=[
            Reference(
                title="OWASP Web Security Testing Guide",
                url="https://owasp.org/www-project-web-security-testing-guide/",
            )
        ],
        limitations=limitations,
    )

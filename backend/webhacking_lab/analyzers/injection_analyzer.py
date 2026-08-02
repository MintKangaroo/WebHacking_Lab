"""Passive SQL error and parameter-context indicators."""

import re

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

DBMS_ERRORS = {
    "PostgreSQL": re.compile(r"(?:postgresql|pg_query|syntax error at or near)", re.IGNORECASE),
    "MySQL": re.compile(
        r"(?:you have an error in your sql syntax|mysql_fetch|mysqli_)", re.IGNORECASE
    ),
    "SQLite": re.compile(
        r"(?:sqlite3?\.(?:operational)?error|near .+: syntax error)", re.IGNORECASE
    ),
    "SQL Server": re.compile(r"(?:sql server|unclosed quotation mark|odbc sql)", re.IGNORECASE),
    "Oracle": re.compile(r"(?:ora-\d{5}|oracle error)", re.IGNORECASE),
}


class InjectionIndicatorAnalyzer:
    """Identify DBMS error disclosure without generating extraction payloads."""

    name = "injection-indicator-analyzer"
    category = VulnerabilityCategory.SQL_INJECTION

    async def analyze(
        self,
        request: NormalizedRequest,
        response: NormalizedResponse | None,
        context: AnalysisContext,
    ) -> AnalysisResult:
        del context
        body = response.body if response else ""
        matches = [name for name, pattern in DBMS_ERRORS.items() if pattern.search(body)]
        parameters = [item.name for item in request.query if not item.redacted]
        suspicious = bool(matches and parameters)
        return AnalysisResult(
            analyzer=self.name,
            category=self.category,
            title="SQL injection indicators",
            summary=(
                f"A {', '.join(matches)} error signature was observed near user-controlled inputs."
                if matches
                else "No known DBMS error signature was observed in the captured response."
            ),
            evidence=[
                Evidence(
                    title="DBMS error fingerprint",
                    detail=name,
                    location="response.body",
                )
                for name in matches
            ]
            + [
                Evidence(
                    title="Candidate input parameter",
                    detail=name,
                    location="request.query",
                )
                for name in parameters[:3]
            ]
            if matches
            else [],
            hypotheses=[
                Hypothesis(
                    title="A query parameter may reach SQL construction",
                    rationale=(
                        "An error fingerprint is a signal; controlled response comparison "
                        "is required."
                    ),
                    status=VerificationStatus.LIKELY
                    if suspicious
                    else VerificationStatus.SUSPICIOUS,
                )
            ]
            if matches
            else [],
            safe_test_cases=[
                TestCase(
                    title="Single syntax-difference observation",
                    objective=(
                        "Compare one quoted input against the baseline without data extraction."
                    ),
                    parameter=parameters[0],
                    mutation_type="query_append",
                    preview_value="'",
                    expected_signal=["DBMS error change", "status or normalized-body difference"],
                    risk_level=RiskLevel.LOW,
                )
            ]
            if suspicious
            else [],
            confidence=0.8 if suspicious else 0.5 if matches else 0.65,
            severity=Severity.HIGH if suspicious else Severity.LOW if matches else Severity.INFO,
            status=(
                VerificationStatus.LIKELY
                if suspicious
                else VerificationStatus.SUSPICIOUS
                if matches
                else VerificationStatus.FALSE_POSITIVE
            ),
            remediation=[
                "Use parameterized queries for every untrusted value.",
                "Return generic errors to clients and keep detailed DB errors in protected logs.",
            ]
            if matches
            else [],
            references=[
                Reference(
                    title="OWASP SQL Injection Prevention Cheat Sheet",
                    url="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                )
            ],
            limitations=[
                (
                    "Error text can be synthetic or unrelated; this analyzer never confirms "
                    "injection alone."
                ),
                "No enumeration, data extraction, file access, or modifying SQL is generated.",
            ],
        )

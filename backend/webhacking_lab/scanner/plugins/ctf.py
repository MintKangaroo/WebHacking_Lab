"""CTF-profile active plugins that send real, read-only detection payloads.

These plugins are only ever reachable when the server operator has explicitly set
``WEBHACKING_CTF_MODE_ENABLED`` and the target was authorized for a CTF workspace.
Every probe is a single GET request with one query parameter replaced, carries no
request body or stored credentials, and is filtered by the CTF non-destructive-value
policy in :mod:`webhacking_lab.scanner.execution_policy`.
"""

import re
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

CTF_PROFILES = frozenset({ScannerProfile.CTF})

XSS_MARKER = "WHL_CTF_XSS_9K2Z"
XSS_PAYLOAD = f'"><script>{XSS_MARKER}</script>'
PASSWD_PATTERN = re.compile(r"root:.*?:0:0:", re.MULTILINE)
REDIRECT_PARAM_HINTS = ("next", "url", "redirect", "return", "return_to", "dest", "go", "to", "r")
FILE_PARAM_HINTS = ("file", "path", "page", "template", "doc", "include", "name", "view")
REDIRECT_TARGET = "https://whl-ctf-redirect.example/probe"


def _response(exchange: HttpExchange) -> NormalizedResponse:
    return NormalizedResponse(
        status_code=exchange.status_code,
        headers=[NameValue(name=name, value=value) for name, value in exchange.headers],
        body=exchange.body,
        elapsed_ms=exchange.elapsed_ms,
    )


def _is_html(exchange: HttpExchange) -> bool:
    return any(
        name.lower() == "content-type" and "html" in value.lower()
        for name, value in exchange.headers
    )


def _header(exchange: HttpExchange, header: str) -> str | None:
    return next(
        (value for name, value in exchange.headers if name.lower() == header.lower()),
        None,
    )


def _first_query(endpoint: ActiveEndpoint) -> str | None:
    parameter = next((item for item in endpoint.parameters if item.location == "query"), None)
    return parameter.name if parameter else None


def _preferred_query(endpoint: ActiveEndpoint, hints: tuple[str, ...]) -> str | None:
    query = [item for item in endpoint.parameters if item.location == "query"]
    for item in query:
        if any(hint in item.name.lower() for hint in hints):
            return item.name
    return query[0].name if query else None


class CtfSqlInjectionPlugin:
    """Error, UNION marker, and boolean probes; it never extracts row data."""

    plugin_id = "ctf-sql-injection"
    category = VulnerabilityCategory.SQL_INJECTION
    supported_profiles = CTF_PROFILES
    success_criteria = (
        "A new DBMS error appears, or a true condition matches baseline while the false "
        "condition differs materially."
    )
    false_positive_notes = "Validation errors, caching, and dynamic pages can also differ."
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
        base = parameter.sample_value or "1"
        plans = [
            TestCase(
                title="SQL error probe",
                objective="Observe whether a single unmatched quote raises a DBMS error.",
                parameter=parameter.name,
                mutation_type="ctf_sql_error",
                preview_value=f"{base}'",
                expected_signal=["new DBMS error signature"],
                risk_level=RiskLevel.MEDIUM,
                requires_confirmation=False,
            ),
            TestCase(
                title="SQL UNION column probe",
                objective="Observe whether a read-only UNION marker changes the response.",
                parameter=parameter.name,
                mutation_type="ctf_sql_union",
                preview_value=f"{base}' UNION SELECT NULL-- -",
                expected_signal=["new DBMS error", "materially different response"],
                risk_level=RiskLevel.MEDIUM,
                requires_confirmation=False,
            ),
            TestCase(
                title="SQL boolean true probe",
                objective="Compare a read-only always-true condition with the baseline.",
                parameter=parameter.name,
                mutation_type="ctf_sql_boolean_true",
                preview_value=f"{base}' OR '1'='1",
                expected_signal=["response remains similar to baseline"],
                risk_level=RiskLevel.MEDIUM,
                requires_confirmation=False,
            ),
            TestCase(
                title="SQL boolean false probe",
                objective="Compare a read-only always-false condition with the baseline.",
                parameter=parameter.name,
                mutation_type="ctf_sql_boolean_false",
                preview_value=f"{base}' OR '1'='2",
                expected_signal=["normalized response differs from baseline"],
                risk_level=RiskLevel.MEDIUM,
                requires_confirmation=False,
            ),
        ]
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
                    summary=(
                        f"A controlled payload introduced a {', '.join(added)} error signature."
                    ),
                    status=VerificationStatus.CONFIRMED,
                    confidence=0.93,
                    severity=Severity.HIGH,
                    evidence=[
                        Evidence(title="New DBMS error", detail=name, location="response.body")
                        for name in added
                    ],
                    remediation=self.remediation,
                    limitations=["This confirms an injectable error path, not extracted data."],
                )
        true_exchange = next(
            (item for item in test_exchanges if item.mutation_type == "ctf_sql_boolean_true"), None
        )
        false_exchange = next(
            (item for item in test_exchanges if item.mutation_type == "ctf_sql_boolean_false"), None
        )
        if true_exchange is not None and false_exchange is not None:
            comparator = DiffAnalyzer()
            true_diff = comparator.compare(_response(baseline), _response(true_exchange))
            false_diff = comparator.compare(_response(baseline), _response(false_exchange))
            if true_diff.body_similarity >= 0.96 and false_diff.body_similarity <= 0.85:
                return result(
                    analyzer=self.plugin_id,
                    category=self.category,
                    title="Runtime SQL boolean signal",
                    summary=(
                        "The true condition matched baseline while the false condition differed."
                    ),
                    status=VerificationStatus.LIKELY,
                    confidence=0.85,
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
                    limitations=["Repeat manually to rule out caching or dynamic content."],
                )
        return result(
            analyzer=self.plugin_id,
            category=self.category,
            title="No reliable SQL injection signal",
            summary="CTF SQL probes did not produce a reliable error or boolean signal.",
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.7,
            severity=Severity.INFO,
            evidence=[],
            remediation=self.remediation,
            limitations=["A negative bounded test does not prove the parameter is safe."],
        )


class CtfReflectedXssPlugin:
    """Send one marker script tag and check whether it is reflected unescaped."""

    plugin_id = "ctf-reflected-xss"
    category = VulnerabilityCategory.XSS
    supported_profiles = CTF_PROFILES
    success_criteria = "The exact unescaped script marker is returned in an HTML response."
    false_positive_notes = "A reflected marker inside an attribute or comment may not execute."
    remediation: ClassVar[list[str]] = [
        "Contextually encode untrusted output and enforce a restrictive CSP."
    ]

    async def create_test_plan(
        self, endpoint: ActiveEndpoint, context: ScanContext
    ) -> list[TestCase]:
        del context
        parameter = _first_query(endpoint)
        if parameter is None:
            return []
        return [
            TestCase(
                title="Reflected XSS marker",
                objective="Check whether a marker script tag is reflected without encoding.",
                parameter=parameter,
                mutation_type="ctf_xss_reflection",
                preview_value=XSS_PAYLOAD,
                expected_signal=["exact unescaped script marker in an HTML response"],
                risk_level=RiskLevel.MEDIUM,
                requires_confirmation=False,
            )
        ]

    async def evaluate(
        self, baseline: HttpExchange, test_exchanges: list[HttpExchange], context: ScanContext
    ) -> AnalysisResult:
        del baseline, context
        reflected = next(
            (item for item in test_exchanges if XSS_PAYLOAD in item.body and _is_html(item)),
            None,
        )
        if reflected is not None:
            return result(
                analyzer=self.plugin_id,
                category=self.category,
                title="Reflected XSS confirmed",
                summary="The exact script marker was reflected unescaped in an HTML response.",
                status=VerificationStatus.CONFIRMED,
                confidence=0.9,
                severity=Severity.HIGH,
                evidence=[
                    Evidence(
                        title="Unescaped marker reflected",
                        detail=XSS_MARKER,
                        location="response.body",
                    )
                ],
                remediation=self.remediation,
                limitations=["Execution context depends on where the marker lands in the DOM."],
            )
        return result(
            analyzer=self.plugin_id,
            category=self.category,
            title="No unescaped reflection observed",
            summary="The script marker was not reflected unescaped in an HTML response.",
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.7,
            severity=Severity.INFO,
            evidence=[],
            remediation=self.remediation,
            limitations=["Alternate encodings or sinks may still be exploitable."],
        )


class CtfPathTraversalPlugin:
    """Request a canonical /etc/passwd traversal and check for its signature only."""

    plugin_id = "ctf-path-traversal"
    category = VulnerabilityCategory.PATH_TRAVERSAL
    supported_profiles = CTF_PROFILES
    success_criteria = "The response body contains a Unix passwd root-line signature."
    false_positive_notes = "A page that echoes the payload without reading a file is not a hit."
    remediation: ClassVar[list[str]] = [
        "Resolve and validate paths against an allowlisted base directory.",
        "Never pass user input directly to file or include APIs.",
    ]

    async def create_test_plan(
        self, endpoint: ActiveEndpoint, context: ScanContext
    ) -> list[TestCase]:
        del context
        parameter = _preferred_query(endpoint, FILE_PARAM_HINTS)
        if parameter is None:
            return []
        return [
            TestCase(
                title="Path traversal to /etc/passwd",
                objective="Check whether the parameter reads an arbitrary file via traversal.",
                parameter=parameter,
                mutation_type="ctf_path_traversal",
                preview_value="../../../../../../etc/passwd",
                expected_signal=["Unix passwd root-line signature in the response"],
                risk_level=RiskLevel.HIGH,
                requires_confirmation=False,
            ),
            TestCase(
                title="Path traversal with dot-bypass",
                objective="Check a ....// filter bypass toward /etc/passwd.",
                parameter=parameter,
                mutation_type="ctf_path_traversal",
                preview_value="....//....//....//....//etc/passwd",
                expected_signal=["Unix passwd root-line signature in the response"],
                risk_level=RiskLevel.HIGH,
                requires_confirmation=False,
            ),
        ]

    async def evaluate(
        self, baseline: HttpExchange, test_exchanges: list[HttpExchange], context: ScanContext
    ) -> AnalysisResult:
        del context
        baseline_hit = bool(PASSWD_PATTERN.search(baseline.body))
        hit = next(
            (
                item
                for item in test_exchanges
                if PASSWD_PATTERN.search(item.body) and not baseline_hit
            ),
            None,
        )
        if hit is not None:
            return result(
                analyzer=self.plugin_id,
                category=self.category,
                title="Path traversal confirmed",
                summary="A traversal payload returned a Unix passwd root-line signature.",
                status=VerificationStatus.CONFIRMED,
                confidence=0.92,
                severity=Severity.HIGH,
                evidence=[
                    Evidence(
                        title="passwd signature",
                        detail="root:...:0:0:",
                        location="response.body",
                    )
                ],
                remediation=self.remediation,
                limitations=["Confirms arbitrary file read on this parameter and payload only."],
            )
        return result(
            analyzer=self.plugin_id,
            category=self.category,
            title="No file-read signature observed",
            summary="CTF traversal payloads did not return a readable file signature.",
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.68,
            severity=Severity.INFO,
            evidence=[],
            remediation=self.remediation,
            limitations=["Other files, encodings, or wrappers may still be reachable."],
        )


class CtfOpenRedirectPlugin:
    """Set a redirect-like parameter to an external URL and read the Location only."""

    plugin_id = "ctf-open-redirect"
    category = VulnerabilityCategory.OPEN_REDIRECT
    supported_profiles = CTF_PROFILES
    success_criteria = "A 3xx Location header points at the externally supplied host."
    false_positive_notes = "A relative or same-host Location is not an open redirect."
    remediation: ClassVar[list[str]] = [
        "Redirect only to an allowlist of known-safe relative paths or hosts."
    ]

    async def create_test_plan(
        self, endpoint: ActiveEndpoint, context: ScanContext
    ) -> list[TestCase]:
        del context
        parameter = next(
            (
                item.name
                for item in endpoint.parameters
                if item.location == "query"
                and any(hint in item.name.lower() for hint in REDIRECT_PARAM_HINTS)
            ),
            None,
        )
        if parameter is None:
            return []
        return [
            TestCase(
                title="Open redirect probe",
                objective="Check whether the redirect parameter honors an external host.",
                parameter=parameter,
                mutation_type="ctf_open_redirect",
                preview_value=REDIRECT_TARGET,
                expected_signal=["3xx Location header to the external host"],
                risk_level=RiskLevel.LOW,
                requires_confirmation=False,
            )
        ]

    async def evaluate(
        self, baseline: HttpExchange, test_exchanges: list[HttpExchange], context: ScanContext
    ) -> AnalysisResult:
        del baseline, context
        for exchange in test_exchanges:
            location = _header(exchange, "location")
            if (
                exchange.status_code in {301, 302, 303, 307, 308}
                and location is not None
                and location.startswith("https://whl-ctf-redirect.example")
            ):
                return result(
                    analyzer=self.plugin_id,
                    category=self.category,
                    title="Open redirect confirmed",
                    summary="A redirect parameter sent the response to an external host.",
                    status=VerificationStatus.CONFIRMED,
                    confidence=0.9,
                    severity=Severity.MEDIUM,
                    evidence=[
                        Evidence(title="Location", detail=location, location="response.headers")
                    ],
                    remediation=self.remediation,
                    limitations=["Impact depends on how the redirect is used downstream."],
                )
        return result(
            analyzer=self.plugin_id,
            category=self.category,
            title="No external redirect observed",
            summary="The redirect parameter did not send the response to the external host.",
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.7,
            severity=Severity.INFO,
            evidence=[],
            remediation=self.remediation,
            limitations=["Client-side redirects are not observed by this bounded check."],
        )

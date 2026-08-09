"""SAFE plugin contract, deny policy, planning, and evidence evaluation tests."""

from uuid import uuid4

import pytest

from webhacking_lab.analyzers.models import TestCase as AnalyzerTestCase
from webhacking_lab.domain.enums import RiskLevel, ScannerProfile, VerificationStatus
from webhacking_lab.domain.exceptions import ExecutionPolicyError
from webhacking_lab.http_client.request_normalizer import normalize_request
from webhacking_lab.scanner.execution_policy import build_safe_test_request
from webhacking_lab.scanner.models import (
    ActiveEndpoint,
    ActiveTestPolicy,
    DiscoveredParameter,
    HttpExchange,
    ScanContext,
    ScanJobCreate,
    ScanTestsApproval,
)
from webhacking_lab.scanner.plugins.cors import ORIGIN, CorsProbePlugin
from webhacking_lab.scanner.plugins.open_redirect import REDIRECT_MARKER, OpenRedirectPlugin
from webhacking_lab.scanner.plugins.reflected_xss import MARKER, ReflectedXssPlugin
from webhacking_lab.scanner.plugins.security_headers import SecurityHeaderPlugin
from webhacking_lab.scanner.plugins.sql_injection import SqlInjectionPlugin
from webhacking_lab.scanner.test_planner import plan_safe_tests


def _context(max_tests: int = 6) -> ScanContext:
    return ScanContext(
        scan_id=uuid4(),
        profile=ScannerProfile.SAFE,
        active_policy=ActiveTestPolicy(enabled=True, max_tests=max_tests),
    )


def _endpoint(url: str = "https://authorized.example/?id=1&next=%2Fhome") -> ActiveEndpoint:
    return ActiveEndpoint(
        url=url,
        method="GET",
        parameters=[
            DiscoveredParameter(
                endpoint_url=url,
                name="id",
                location="query",
                sample_value="1",
                source="seed",
            ),
            DiscoveredParameter(
                endpoint_url=url,
                name="next",
                location="query",
                sample_value="/home",
                source="seed",
            ),
        ],
        baseline_request_id=uuid4(),
        baseline_response_id=uuid4(),
    )


def _exchange(
    *,
    body: str = "baseline",
    headers: list[tuple[str, str]] | None = None,
    mutation_type: str | None = None,
    status_code: int = 200,
) -> HttpExchange:
    return HttpExchange(
        request_id=uuid4(),
        response_id=uuid4(),
        method="GET",
        url="https://authorized.example/?id=1",
        status_code=status_code,
        headers=headers or [("Content-Type", "text/html")],
        body=body,
        elapsed_ms=2,
        mutation_type=mutation_type,
    )


def test_central_safe_mutation_policy_allows_only_bounded_query_or_cors() -> None:
    baseline = normalize_request(
        method="GET",
        url="https://authorized.example/?id=1",
        max_body_bytes=0,
    )
    safe = AnalyzerTestCase(
        title="quote",
        objective="observe",
        parameter="id",
        mutation_type="sql_quote_append",
        preview_value="1'",
        expected_signal=["error"],
        risk_level=RiskLevel.LOW,
    )
    assert build_safe_test_request(baseline, safe).url.endswith("id=1%27")
    cors = safe.model_copy(
        update={
            "parameter": None,
            "mutation_type": "cors_reserved_origin",
            "preview_value": ORIGIN,
        }
    )
    cors_request = build_safe_test_request(baseline, cors)
    assert cors_request.method == "OPTIONS"
    assert {item.name for item in cors_request.headers} >= {
        "Origin",
        "Access-Control-Request-Method",
    }

    for blocked in (
        safe.model_copy(update={"destructive": True}),
        safe.model_copy(update={"preview_value": "1; DROP TABLE users"}),
        safe.model_copy(update={"mutation_type": "command_execution"}),
        safe.model_copy(update={"parameter": "missing"}),
    ):
        with pytest.raises(ExecutionPolicyError):
            build_safe_test_request(baseline, blocked)


@pytest.mark.asyncio
async def test_planner_generates_six_exact_previews_and_skips_secrets() -> None:
    planned = await plan_safe_tests(_endpoint(), _context())
    assert len(planned) == 6
    assert {item.plugin.plugin_id for item in planned} == {
        "safe-sql-injection",
        "safe-reflected-xss",
        "safe-open-redirect",
        "safe-cors-probe",
    }
    assert all("Host: authorized.example" in item.exact_request for item in planned)

    sensitive_endpoint = _endpoint("https://authorized.example/?token=%5BREDACTED%5D")
    sensitive_endpoint = sensitive_endpoint.model_copy(
        update={
            "parameters": [
                DiscoveredParameter(
                    endpoint_url=sensitive_endpoint.url,
                    name="token",
                    location="query",
                    sample_value="[REDACTED]",
                    source="seed",
                )
            ]
        }
    )
    sensitive_plans = await plan_safe_tests(sensitive_endpoint, _context())
    assert len(sensitive_plans) == 1
    assert sensitive_plans[0].plugin.plugin_id == "safe-cors-probe"


@pytest.mark.asyncio
async def test_sql_plugin_distinguishes_error_boolean_and_no_signal() -> None:
    plugin = SqlInjectionPlugin()
    plans = await plugin.create_test_plan(_endpoint(), _context())
    assert {item.mutation_type for item in plans} == {
        "sql_quote_append",
        "sql_boolean_true",
        "sql_boolean_false",
    }
    baseline = _exchange(body="same content")
    error = await plugin.evaluate(
        baseline,
        [_exchange(body="sqlite3.OperationalError: near value: syntax error")],
        _context(),
    )
    assert error.status == VerificationStatus.CONFIRMED
    probable = await plugin.evaluate(
        baseline,
        [
            _exchange(body="same content", mutation_type="sql_boolean_true"),
            _exchange(body="access denied and no rows", mutation_type="sql_boolean_false"),
        ],
        _context(),
    )
    assert probable.status == VerificationStatus.LIKELY
    none = await plugin.evaluate(baseline, [_exchange(body="same content")], _context())
    assert none.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_reflection_redirect_and_cors_plugins_do_not_overstate_signals() -> None:
    baseline = _exchange()
    xss = ReflectedXssPlugin()
    assert len(await xss.create_test_plan(_endpoint(), _context())) == 1
    reflected = await xss.evaluate(
        baseline,
        [_exchange(body=f"<p>{MARKER}</p>")],
        _context(),
    )
    assert reflected.status == VerificationStatus.LIKELY
    assert (
        await xss.evaluate(baseline, [_exchange(body="encoded")], _context())
    ).status == VerificationStatus.FALSE_POSITIVE

    redirect = OpenRedirectPlugin()
    assert len(await redirect.create_test_plan(_endpoint(), _context())) == 1
    confirmed = await redirect.evaluate(
        baseline,
        [_exchange(status_code=302, headers=[("Location", REDIRECT_MARKER)])],
        _context(),
    )
    assert confirmed.status == VerificationStatus.CONFIRMED
    assert (
        await redirect.evaluate(baseline, [_exchange()], _context())
    ).status == VerificationStatus.FALSE_POSITIVE

    cors = CorsProbePlugin()
    assert len(await cors.create_test_plan(_endpoint(), _context())) == 1
    permissive = await cors.evaluate(
        baseline,
        [
            _exchange(
                headers=[
                    ("Access-Control-Allow-Origin", ORIGIN),
                    ("Access-Control-Allow-Credentials", "true"),
                ]
            )
        ],
        _context(),
    )
    assert permissive.status == VerificationStatus.LIKELY
    assert (
        await cors.evaluate(baseline, [_exchange()], _context())
    ).status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_security_header_active_adapter_never_generates_a_request() -> None:
    plugin = SecurityHeaderPlugin()
    assert await plugin.create_test_plan(_endpoint(), _context()) == []
    result = await plugin.evaluate(_exchange(), [], _context())
    assert result.status == VerificationStatus.NOT_TESTED


def test_scan_models_reject_profile_confusion_and_duplicate_approval() -> None:
    base = {
        "project_id": uuid4(),
        "workspace_id": uuid4(),
        "target": "https://authorized.example/",
        "authorization_confirmed": True,
        "expected_use": "Authorized bounded scanner regression",
    }
    invalid_inputs = (
        {**base, "profile": "passive", "confirmation_phrase": "START SAFE SCAN"},
        {
            **base,
            "profile": "passive",
            "confirmation_phrase": "START PASSIVE SCAN",
            "active_test_policy": {"enabled": True},
        },
        {**base, "profile": "safe", "confirmation_phrase": "START SAFE SCAN"},
    )
    for invalid in invalid_inputs:
        with pytest.raises(ValueError):
            ScanJobCreate.model_validate(invalid)
    test_id = uuid4()
    with pytest.raises(ValueError):
        ScanTestsApproval(
            test_ids=[test_id, test_id],
            authorization_confirmed=True,
            confirmation_phrase="APPROVE SELECTED SAFE TESTS",
        )

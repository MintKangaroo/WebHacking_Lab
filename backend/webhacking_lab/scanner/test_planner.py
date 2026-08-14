"""Turn runtime inventory into exact, bounded, never-auto-run SAFE requests."""

from dataclasses import dataclass

from webhacking_lab.analyzers.models import TestCase
from webhacking_lab.core.redaction import REDACTED, is_sensitive_name
from webhacking_lab.domain.enums import RiskLevel, ScannerProfile
from webhacking_lab.http_client.models import NormalizedRequest
from webhacking_lab.http_client.request_normalizer import normalize_request, render_raw_request
from webhacking_lab.scanner.execution_policy import build_test_request
from webhacking_lab.scanner.models import ActiveEndpoint, ScanContext
from webhacking_lab.scanner.plugins import CTF_ACTIVE_PLUGINS, SAFE_ACTIVE_PLUGINS
from webhacking_lab.scanner.plugins.base import ActiveScannerPlugin

# SAFE stays limited to the lowest-risk mutations; CTF intentionally allows the
# higher-risk read-only detection payloads because the operator opted into it.
SAFE_RISK_ALLOWLIST = frozenset({RiskLevel.INFO, RiskLevel.LOW})


@dataclass(frozen=True)
class PlannedTest:
    """Plugin plan plus the centrally rendered exact request."""

    plugin: ActiveScannerPlugin
    test_case: TestCase
    exact_request: str
    normalized_request: NormalizedRequest


def _plugins_for(profile: ScannerProfile) -> tuple[ActiveScannerPlugin, ...]:
    if profile == ScannerProfile.CTF:
        return CTF_ACTIVE_PLUGINS
    return SAFE_ACTIVE_PLUGINS


async def plan_safe_tests(endpoint: ActiveEndpoint, context: ScanContext) -> list[PlannedTest]:
    """Create a small ordered plan while filtering secret-shaped parameters."""

    safe_parameters = [
        item
        for item in endpoint.parameters
        if not is_sensitive_name(item.name) and item.sample_value != REDACTED
    ]
    safe_endpoint = endpoint.model_copy(update={"parameters": safe_parameters})
    baseline = normalize_request(method="GET", url=endpoint.url, max_body_bytes=0)
    planned: list[PlannedTest] = []
    per_parameter: dict[str, int] = {}
    for plugin in _plugins_for(context.profile):
        if context.profile not in plugin.supported_profiles:
            continue
        for test_case in await plugin.create_test_plan(safe_endpoint, context):
            parameter_key = test_case.parameter or "<endpoint>"
            if per_parameter.get(parameter_key, 0) >= context.active_policy.max_tests_per_parameter:
                continue
            if test_case.destructive:
                continue
            if (
                context.profile != ScannerProfile.CTF
                and test_case.risk_level not in SAFE_RISK_ALLOWLIST
            ):
                continue
            mutated = build_test_request(baseline, test_case, profile=context.profile)
            planned.append(
                PlannedTest(
                    plugin=plugin,
                    test_case=test_case,
                    exact_request=render_raw_request(mutated),
                    normalized_request=mutated,
                )
            )
            per_parameter[parameter_key] = per_parameter.get(parameter_key, 0) + 1
            if len(planned) >= context.active_policy.max_tests:
                return planned
    return planned

"""Scan creation, explicit test approval, cancellation, and read models."""

import ipaddress
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.core.config import Settings
from webhacking_lab.database.models import ScanEvent, ScanJob, ScanTestCase, ScopeRule
from webhacking_lab.database.repositories.audit import AuditRepository
from webhacking_lab.database.repositories.projects import (
    ProjectRepository,
    ScopeRuleRepository,
    WorkspaceRepository,
)
from webhacking_lab.database.repositories.scans import ScanRepository
from webhacking_lab.domain.enums import (
    ActiveTestStatus,
    AuditEventType,
    ScannerProfile,
    ScanStatus,
    VerificationStatus,
)
from webhacking_lab.domain.exceptions import (
    ConflictError,
    EntityNotFoundError,
    ExecutionPolicyError,
)
from webhacking_lab.http_client.models import ScopeRuleSpec
from webhacking_lab.http_client.request_normalizer import normalize_request
from webhacking_lab.http_client.scope_guard import DnsResolver, ScopeGuard
from webhacking_lab.scanner.models import (
    ActiveTestPolicy,
    CrawlPolicy,
    ScanCancelRead,
    ScanEndpointRead,
    ScanEventRead,
    ScanFindingRead,
    ScanJobCreate,
    ScanJobRead,
    ScanParameterRead,
    ScanTestCaseRead,
    ScanTestsApproval,
    ScanTestsApprovalRead,
    TechnologyFingerprint,
)

TERMINAL_SCAN_STATES = frozenset(
    {ScanStatus.COMPLETED, ScanStatus.CANCELLED, ScanStatus.FAILED, ScanStatus.BLOCKED}
)


def _is_loopback(hostname: str) -> bool:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def scan_job_read(job: ScanJob) -> ScanJobRead:
    """Convert a loaded job aggregate into the public representation."""

    return ScanJobRead(
        id=job.id,
        project_id=job.project_id,
        workspace_id=job.workspace_id,
        profile=job.profile,
        target=job.target,
        status=job.status,
        current_stage=job.current_stage,
        progress=job.progress,
        request_budget=job.request_budget,
        requests_used=job.requests_used,
        endpoints_count=len(job.endpoints),
        parameters_count=len(job.parameters),
        findings_count=job.findings_count,
        cancellation_requested=job.cancellation_requested,
        crawl_policy=CrawlPolicy.model_validate(job.crawl_policy_json),
        active_test_policy=ActiveTestPolicy.model_validate(
            job.metadata_json.get("active_test_policy", {})
        ),
        planned_tests_count=len(job.test_cases),
        approved_tests_count=sum(
            item.status != ActiveTestStatus.PREVIEW for item in job.test_cases
        ),
        fingerprints=[
            TechnologyFingerprint.model_validate(value)
            for value in job.fingerprint_json.get("signals", [])
        ],
        error_message=job.error_message,
        started_at=job.started_at,
        finished_at=job.finished_at,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


class ScanService:
    """Own all user-triggered scan state transitions outside the crawler task."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        resolver: DnsResolver,
    ) -> None:
        self._session = session
        self._settings = settings
        self._guard = ScopeGuard(resolver)
        self._projects = ProjectRepository(session)
        self._workspaces = WorkspaceRepository(session)
        self._scopes = ScopeRuleRepository(session)
        self._scans = ScanRepository(session)
        self._audit = AuditRepository(session)

    @staticmethod
    def _scope_specs(rules: list[ScopeRule]) -> list[ScopeRuleSpec]:
        return [
            ScopeRuleSpec(
                id=rule.id,
                scheme=rule.scheme,
                hostname=rule.hostname,
                port=rule.port,
                path_prefix=rule.path_prefix,
                allow_subdomains=rule.allow_subdomains,
                max_requests_per_minute=rule.max_requests_per_minute,
                max_concurrency=rule.max_concurrency,
                authorization_confirmed=rule.authorization_confirmed,
            )
            for rule in rules
        ]

    async def _register_ctf_scope(self, project_id: UUID, target_url: str) -> ScopeRule:
        """Register the pasted CTF target host as a pre-authorized scope rule."""

        parsed = urlsplit(target_url)
        return await self._scopes.add(
            ScopeRule(
                project_id=project_id,
                scheme=parsed.scheme,
                hostname=(parsed.hostname or "").lower(),
                port=parsed.port,
                path_prefix="/",
                allow_subdomains=False,
                max_requests_per_minute=self._settings.global_requests_per_minute,
                max_concurrency=self._settings.default_target_concurrency,
                authorization_confirmed=True,
                authorization_notes=(
                    "Auto-registered for a CTF scan (operator opted in via CTF mode)."
                ),
            )
        )

    async def create(self, data: ScanJobCreate, correlation_id: str | None) -> ScanJobRead:
        """Persist a validated passive, SAFE, or CTF plan; no request is sent here."""

        if self._settings.analysis_only or not self._settings.network_execution_enabled:
            raise ExecutionPolicyError("URL scanning is disabled by the server safety policy")
        if data.profile == ScannerProfile.CTF and not self._settings.ctf_mode_enabled:
            raise ExecutionPolicyError(
                "CTF scanning is disabled; set WEBHACKING_CTF_MODE_ENABLED=true to allow it"
            )
        if data.profile not in {
            ScannerProfile.PASSIVE,
            ScannerProfile.SAFE,
            ScannerProfile.CTF,
        }:
            raise ExecutionPolicyError(
                "Only PASSIVE, SAFE, and CTF scanner profiles are implemented"
            )
        if data.crawl_policy.execute_javascript:
            raise ExecutionPolicyError(
                "Browser JavaScript execution is not available in passive scans"
            )
        project = await self._projects.get(data.project_id)
        workspace = await self._workspaces.get(data.workspace_id)
        if project is None or workspace is None or workspace.project_id != data.project_id:
            raise EntityNotFoundError("Project or workspace was not found")
        if not workspace.network_execution_enabled:
            if data.profile == ScannerProfile.CTF:
                # Full CTF gate relaxation: the operator already opted in via the
                # server flag, so enable this workspace for network execution instead
                # of forcing a separate manual toggle.
                workspace.network_execution_enabled = True
            else:
                raise ExecutionPolicyError("Network execution is disabled for this workspace")
        remaining_budget = workspace.request_budget - workspace.requests_used
        if remaining_budget <= 0:
            raise ExecutionPolicyError("Workspace request budget is exhausted")
        normalized = normalize_request(
            method="GET",
            url=data.target,
            max_body_bytes=self._settings.max_request_bytes,
        )
        rules = await self._scopes.list_for_project(project.id)
        decision = await self._guard.check(normalized.url, self._scope_specs(rules))
        matched = next((rule for rule in rules if rule.id == decision.matched_rule_id), None)
        if (
            data.profile == ScannerProfile.CTF
            and decision.code == "not_in_scope"
            and matched is None
        ):
            # Scope Guard's SSRF/IP checks already passed (only the allowlist-membership
            # check failed), so auto-register the pasted target as an authorized rule.
            # This bypasses the manual scope + authorization ceremony, never SSRF policy.
            matched = await self._register_ctf_scope(project.id, normalized.url)
            rules = [*rules, matched]
            decision = await self._guard.check(normalized.url, self._scope_specs(rules))
        if not decision.allowed or matched is None:
            raise ExecutionPolicyError(f"Scope Guard blocked the scan target: {decision.reason}")
        if not _is_loopback(normalized.host) and not matched.authorization_confirmed:
            if data.profile == ScannerProfile.CTF:
                matched.authorization_confirmed = True
            else:
                raise ExecutionPolicyError("External scan targets require an authorized scope rule")
        active_limit = 0
        if data.profile in {ScannerProfile.SAFE, ScannerProfile.CTF}:
            if remaining_budget < 2:
                raise ExecutionPolicyError(
                    f"{data.profile.value.upper()} scans require budget for at least one crawl "
                    "and one test"
                )
            active_limit = min(data.active_test_policy.max_tests, remaining_budget - 1)
        effective_request_limit = min(
            data.crawl_policy.max_requests,
            remaining_budget - active_limit,
        )
        effective_policy = CrawlPolicy.model_validate(
            data.crawl_policy.model_copy(
                update={
                    "max_pages": min(data.crawl_policy.max_pages, effective_request_limit),
                    "max_requests": effective_request_limit,
                    "max_response_bytes": min(
                        data.crawl_policy.max_response_bytes,
                        self._settings.max_response_bytes,
                    ),
                    "requests_per_second": min(
                        data.crawl_policy.requests_per_second,
                        matched.max_requests_per_minute / 60,
                        self._settings.global_requests_per_minute / 60,
                    ),
                }
            )
        )
        job = await self._scans.add_job(
            ScanJob(
                project_id=project.id,
                workspace_id=workspace.id,
                profile=data.profile,
                target=normalized.url,
                status=ScanStatus.QUEUED,
                current_stage="Queued",
                progress=0,
                request_budget=effective_policy.max_requests + active_limit,
                crawl_policy_json=effective_policy.model_dump(mode="json"),
                metadata_json={
                    "expected_use": data.expected_use.strip(),
                    "active_test_policy": data.active_test_policy.model_copy(
                        update={"max_tests": active_limit}
                    ).model_dump(mode="json")
                    if data.profile in {ScannerProfile.SAFE, ScannerProfile.CTF}
                    else ActiveTestPolicy().model_dump(mode="json"),
                },
            )
        )
        await self._scans.add_event(
            ScanEvent(
                scan_id=job.id,
                stage="Queued",
                message={
                    ScannerProfile.SAFE: (
                        "SAFE scan accepted; mutation requests require a second, "
                        "per-test approval."
                    ),
                    ScannerProfile.CTF: (
                        "CTF scan accepted; bounded read-only probes will run unattended "
                        "on the authorized target."
                    ),
                }.get(
                    data.profile,
                    "Passive scan accepted; no mutation tests will be generated.",
                ),
                details_json={
                    "profile": data.profile.value,
                    "maximum_requests": effective_policy.max_requests,
                    "maximum_active_tests": active_limit,
                    "maximum_depth": effective_policy.max_depth,
                    "requests_per_second": effective_policy.requests_per_second,
                },
            )
        )
        await self._audit.record(
            AuditEventType.SCAN_CREATED,
            resource_type="scan_job",
            resource_id=job.id,
            project_id=project.id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
            details={
                "profile": data.profile.value,
                "hostname": normalized.host,
                "maximum_requests": effective_policy.max_requests + active_limit,
                "maximum_active_tests": active_limit,
                "expected_use": data.expected_use.strip(),
            },
        )
        await self._session.commit()
        loaded = await self._scans.get_job(job.id)
        if loaded is None:
            raise EntityNotFoundError("Created scan could not be reloaded")
        return scan_job_read(loaded)

    async def list_jobs(self, project_id: UUID | None) -> list[ScanJobRead]:
        return [scan_job_read(job) for job in await self._scans.list_jobs(project_id)]

    async def get(self, scan_id: UUID) -> ScanJobRead:
        job = await self._scans.get_job(scan_id)
        if job is None:
            raise EntityNotFoundError("Scan job was not found")
        return scan_job_read(job)

    async def cancel(self, scan_id: UUID, correlation_id: str | None) -> ScanCancelRead:
        job = await self._scans.get_job(scan_id)
        if job is None:
            raise EntityNotFoundError("Scan job was not found")
        if job.status in TERMINAL_SCAN_STATES:
            raise ConflictError("A completed scan cannot be cancelled")
        job.cancellation_requested = True
        job.version += 1
        waiting_for_approval = job.status == ScanStatus.WAITING_FOR_APPROVAL
        if waiting_for_approval:
            job.status = ScanStatus.CANCELLED
            job.current_stage = "Cancelled"
            job.finished_at = datetime.now(UTC)
        await self._scans.add_event(
            ScanEvent(
                scan_id=job.id,
                stage=job.current_stage,
                level="warning",
                message=(
                    "Scan cancelled; unapproved SAFE previews were not sent."
                    if waiting_for_approval
                    else "Cancellation requested; the current bounded request may finish first."
                ),
            )
        )
        await self._audit.record(
            AuditEventType.SCAN_CANCELLATION_REQUESTED,
            resource_type="scan_job",
            resource_id=job.id,
            project_id=job.project_id,
            workspace_id=job.workspace_id,
            correlation_id=correlation_id,
        )
        if waiting_for_approval:
            await self._audit.record(
                AuditEventType.SCAN_CANCELLED,
                resource_type="scan_job",
                resource_id=job.id,
                project_id=job.project_id,
                workspace_id=job.workspace_id,
                correlation_id=correlation_id,
                details={"requests_used": job.requests_used, "pending_tests_sent": 0},
            )
        await self._session.commit()
        return ScanCancelRead(
            id=job.id,
            cancellation_requested=True,
            status=job.status,
        )

    async def endpoints(self, scan_id: UUID) -> list[ScanEndpointRead]:
        await self.get(scan_id)
        return [
            ScanEndpointRead.model_validate(value)
            for value in await self._scans.list_endpoints(scan_id)
        ]

    async def parameters(self, scan_id: UUID) -> list[ScanParameterRead]:
        await self.get(scan_id)
        return [
            ScanParameterRead.model_validate(value)
            for value in await self._scans.list_parameters(scan_id)
        ]

    async def findings(self, scan_id: UUID) -> list[ScanFindingRead]:
        await self.get(scan_id)
        return [
            ScanFindingRead(
                id=value.id,
                scan_id=value.scan_id,
                endpoint_url=value.endpoint_url,
                analyzer=value.analyzer,
                category=value.category,
                title=value.title,
                summary=value.summary,
                status=value.status,
                severity=value.severity,
                confidence=value.confidence,
                evidence=value.evidence_json,
                remediation=value.remediation_json,
                limitations=value.limitations_json,
                created_at=value.created_at,
            )
            for value in await self._scans.list_findings(scan_id)
            if value.status != VerificationStatus.NOT_TESTED.value
        ]

    async def tests(self, scan_id: UUID) -> list[ScanTestCaseRead]:
        """Return the exact persisted previews and redacted result evidence."""

        await self.get(scan_id)
        return [self._test_read(value) for value in await self._scans.list_test_cases(scan_id)]

    @staticmethod
    def _test_read(value: ScanTestCase) -> ScanTestCaseRead:
        return ScanTestCaseRead(
            id=value.id,
            scan_id=value.scan_id,
            plugin_id=value.plugin_id,
            category=value.category,
            endpoint_url=value.endpoint_url,
            method=value.method,
            title=value.title,
            objective=value.objective,
            parameter=value.parameter,
            mutation_type=value.mutation_type,
            preview_value=value.preview_value,
            exact_request_preview=value.exact_request_preview,
            expected_signals=value.expected_signals_json,
            success_criteria=value.success_criteria,
            false_positive_notes=value.false_positive_notes,
            remediation=value.remediation_json,
            risk_level=value.risk_level,
            maximum_requests=value.maximum_requests,
            destructive=value.destructive,
            requires_confirmation=value.requires_confirmation,
            status=value.status,
            result_status=value.result_status,
            confidence=value.confidence,
            evidence=value.evidence_json,
            error_message=value.error_message,
            approved_at=value.approved_at,
            completed_at=value.completed_at,
            created_at=value.created_at,
        )

    async def approve_tests(
        self,
        scan_id: UUID,
        data: ScanTestsApproval,
        correlation_id: str | None,
    ) -> ScanTestsApprovalRead:
        """Approve only selected low-risk previews; background execution starts later."""

        job = await self._scans.get_job(scan_id)
        if job is None:
            raise EntityNotFoundError("Scan job was not found")
        if job.profile != ScannerProfile.SAFE or job.status != ScanStatus.WAITING_FOR_APPROVAL:
            raise ConflictError("Only a SAFE scan waiting for approval can execute tests")
        if job.cancellation_requested:
            raise ConflictError("A cancelled scan cannot approve tests")
        policy = ActiveTestPolicy.model_validate(job.metadata_json.get("active_test_policy", {}))
        if len(data.test_ids) > policy.max_tests:
            raise ExecutionPolicyError("Selected tests exceed the persisted SAFE test ceiling")
        tests: list[ScanTestCase] = []
        for test_id in data.test_ids:
            test = await self._scans.get_test_case(test_id)
            if test is None or test.scan_id != job.id:
                raise ExecutionPolicyError("Every selected test must belong to this scan")
            if (
                test.status != ActiveTestStatus.PREVIEW
                or test.destructive
                or test.maximum_requests != 1
                or test.risk_level not in {"info", "low"}
            ):
                raise ExecutionPolicyError("A selected test violates the SAFE execution policy")
            tests.append(test)
        remaining = job.request_budget - job.requests_used
        if len(tests) > remaining:
            raise ExecutionPolicyError("Selected tests exceed the remaining request budget")
        approved_at = datetime.now(UTC)
        for test in tests:
            test.status = ActiveTestStatus.APPROVED
            test.approved_at = approved_at
        job.status = ScanStatus.ACTIVE_TESTING
        job.current_stage = "Active Testing"
        job.progress = max(job.progress, 0.82)
        await self._scans.add_event(
            ScanEvent(
                scan_id=job.id,
                stage=job.current_stage,
                message="Selected exact requests approved for bounded background execution.",
                details_json={"test_ids": [str(value.id) for value in tests]},
            )
        )
        await self._audit.record(
            AuditEventType.SCAN_TESTS_APPROVED,
            resource_type="scan_job",
            resource_id=job.id,
            project_id=job.project_id,
            workspace_id=job.workspace_id,
            correlation_id=correlation_id,
            details={"test_ids": [str(value.id) for value in tests]},
        )
        await self._session.commit()
        return ScanTestsApprovalRead(
            scan_id=job.id,
            approved_test_ids=[value.id for value in tests],
            status=job.status,
        )

    async def events(self, scan_id: UUID) -> list[ScanEventRead]:
        await self.get(scan_id)
        return [
            ScanEventRead(
                id=value.id,
                scan_id=value.scan_id,
                stage=value.stage,
                level=value.level,
                message=value.message,
                details=value.details_json,
                created_at=value.created_at,
            )
            for value in await self._scans.list_events(scan_id)
        ]

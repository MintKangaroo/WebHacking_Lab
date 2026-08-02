"""Scan job creation, policy validation, cancellation, and read models."""

import ipaddress
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.core.config import Settings
from webhacking_lab.database.models import ScanEvent, ScanJob
from webhacking_lab.database.repositories.audit import AuditRepository
from webhacking_lab.database.repositories.projects import (
    ProjectRepository,
    ScopeRuleRepository,
    WorkspaceRepository,
)
from webhacking_lab.database.repositories.scans import ScanRepository
from webhacking_lab.domain.enums import (
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
    CrawlPolicy,
    ScanCancelRead,
    ScanEndpointRead,
    ScanEventRead,
    ScanFindingRead,
    ScanJobCreate,
    ScanJobRead,
    ScanParameterRead,
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

    async def create(self, data: ScanJobCreate, correlation_id: str | None) -> ScanJobRead:
        """Persist a validated passive plan; no request is sent by this method."""

        if self._settings.analysis_only or not self._settings.network_execution_enabled:
            raise ExecutionPolicyError(
                "Passive URL scanning is disabled by the server safety policy"
            )
        if data.profile != ScannerProfile.PASSIVE:
            raise ExecutionPolicyError("Only the passive scanner profile is implemented in Phase 8")
        if data.crawl_policy.execute_javascript:
            raise ExecutionPolicyError(
                "Browser JavaScript execution is not available in passive scans"
            )
        project = await self._projects.get(data.project_id)
        workspace = await self._workspaces.get(data.workspace_id)
        if project is None or workspace is None or workspace.project_id != data.project_id:
            raise EntityNotFoundError("Project or workspace was not found")
        if not workspace.network_execution_enabled:
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
        specs = [
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
        decision = await self._guard.check(normalized.url, specs)
        matched = next((rule for rule in rules if rule.id == decision.matched_rule_id), None)
        if not decision.allowed or matched is None:
            raise ExecutionPolicyError(f"Scope Guard blocked the scan target: {decision.reason}")
        if not _is_loopback(normalized.host) and not matched.authorization_confirmed:
            raise ExecutionPolicyError("External scan targets require an authorized scope rule")
        effective_request_limit = min(data.crawl_policy.max_requests, remaining_budget)
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
                request_budget=effective_policy.max_requests,
                crawl_policy_json=effective_policy.model_dump(mode="json"),
                metadata_json={"expected_use": data.expected_use.strip()},
            )
        )
        await self._scans.add_event(
            ScanEvent(
                scan_id=job.id,
                stage="Queued",
                message="Passive scan plan accepted; no mutation tests will be generated.",
                details_json={
                    "profile": data.profile.value,
                    "maximum_requests": effective_policy.max_requests,
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
                "maximum_requests": effective_policy.max_requests,
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
        await self._scans.add_event(
            ScanEvent(
                scan_id=job.id,
                stage=job.current_stage,
                level="warning",
                message="Cancellation requested; the current bounded request may finish first.",
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
            if value.status
            in {
                VerificationStatus.OBSERVATION.value,
                VerificationStatus.SUSPICIOUS.value,
                VerificationStatus.LIKELY.value,
            }
        ]

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

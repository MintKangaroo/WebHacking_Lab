"""Sequential, cancellable passive crawler using the shared execution gateway."""

import asyncio
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from time import monotonic
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.analyzers.engine import AnalysisEngine
from webhacking_lab.analyzers.models import AnalysisContext, AnalysisResult
from webhacking_lab.api.schemas.resources import (
    HttpRequestCreate,
    RequestExecutionApproval,
)
from webhacking_lab.core.config import Settings
from webhacking_lab.core.rate_limit import RequestGate
from webhacking_lab.database.models import (
    ScanEndpoint,
    ScanEvent,
    ScanFinding,
    ScanJob,
    ScanParameter,
)
from webhacking_lab.database.repositories.audit import AuditRepository
from webhacking_lab.database.repositories.scans import ScanRepository
from webhacking_lab.database.session import Database
from webhacking_lab.domain.enums import AuditEventType, ScanStatus, VerificationStatus
from webhacking_lab.domain.exceptions import DomainError, ExecutionPolicyError
from webhacking_lab.http_client.client import SingleHopSender
from webhacking_lab.http_client.models import NormalizedRequest
from webhacking_lab.http_client.scope_guard import DnsResolver, ScopeGuard
from webhacking_lab.scanner.crawler import discover_document
from webhacking_lab.scanner.discovery import (
    is_logout_route,
    normalize_discovered_url,
    query_parameters,
    same_crawl_origin,
)
from webhacking_lab.scanner.fingerprint import fingerprint_response
from webhacking_lab.scanner.models import (
    CrawlPolicy,
    DiscoveredEndpoint,
    DiscoveredParameter,
    TechnologyFingerprint,
)
from webhacking_lab.services.http_requests import HttpRequestService
from webhacking_lab.services.request_execution import RequestExecutionService

Sleep = Callable[[float], Awaitable[None]]
Clock = Callable[[], float]


class PassiveScanEngine:
    """Run only static-resource collection and passive analyzers."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        gate: RequestGate,
        sender: SingleHopSender,
        resolver: DnsResolver,
        *,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = monotonic,
    ) -> None:
        self._session = session
        self._settings = settings
        self._gate = gate
        self._sender = sender
        self._resolver = resolver
        self._sleep = sleep
        self._clock = clock
        self._scans = ScanRepository(session)
        self._audit = AuditRepository(session)
        self._analysis = AnalysisEngine()

    async def _event(
        self,
        job: ScanJob,
        message: str,
        *,
        level: str = "info",
        details: dict[str, object] | None = None,
    ) -> None:
        await self._scans.add_event(
            ScanEvent(
                scan_id=job.id,
                stage=job.current_stage,
                level=level,
                message=message,
                details_json=details or {},
            )
        )

    async def _stage(
        self,
        job: ScanJob,
        status: ScanStatus,
        label: str,
        progress: float,
        correlation_id: str | None,
    ) -> None:
        job.status = status
        job.current_stage = label
        job.progress = progress
        await self._event(job, f"Entered {label} stage.")
        await self._audit.record(
            AuditEventType.SCAN_STAGE_CHANGED,
            resource_type="scan_job",
            resource_id=job.id,
            project_id=job.project_id,
            workspace_id=job.workspace_id,
            correlation_id=correlation_id,
            details={"status": status.value, "stage": label, "progress": progress},
        )
        await self._session.commit()

    async def _is_cancelled(self, job: ScanJob, correlation_id: str | None) -> bool:
        await self._session.refresh(job)
        if not job.cancellation_requested:
            return False
        job.status = ScanStatus.CANCELLED
        job.current_stage = "Cancelled"
        job.finished_at = datetime.now(UTC)
        await self._event(job, "Scan cancelled before another request was queued.", level="warning")
        await self._audit.record(
            AuditEventType.SCAN_CANCELLED,
            resource_type="scan_job",
            resource_id=job.id,
            project_id=job.project_id,
            workspace_id=job.workspace_id,
            correlation_id=correlation_id,
            details={"requests_used": job.requests_used},
        )
        await self._session.commit()
        return True

    async def _fail(
        self,
        job: ScanJob,
        status: ScanStatus,
        message: str,
        event_type: AuditEventType,
        correlation_id: str | None,
    ) -> None:
        job.status = status
        job.current_stage = "Blocked" if status == ScanStatus.BLOCKED else "Failed"
        job.error_message = message
        job.finished_at = datetime.now(UTC)
        await self._event(job, message, level="error")
        await self._audit.record(
            event_type,
            resource_type="scan_job",
            resource_id=job.id,
            project_id=job.project_id,
            workspace_id=job.workspace_id,
            correlation_id=correlation_id,
            details={"status": status.value, "requests_used": job.requests_used},
        )
        await self._session.commit()

    async def _pace(self, last_request_at: float | None, policy: CrawlPolicy) -> None:
        if last_request_at is None:
            return
        minimum_interval = 1 / policy.requests_per_second
        remaining = minimum_interval - (self._clock() - last_request_at)
        if remaining > 0:
            await self._sleep(remaining)

    async def run(self, scan_id: UUID, correlation_id: str | None = None) -> None:
        """Run the persisted plan and record terminal state for every exit path."""

        job = await self._scans.get_job(scan_id)
        if job is None:
            return
        try:
            policy = CrawlPolicy.model_validate(job.crawl_policy_json)
            job.started_at = datetime.now(UTC)
            await self._audit.record(
                AuditEventType.SCAN_STARTED,
                resource_type="scan_job",
                resource_id=job.id,
                project_id=job.project_id,
                workspace_id=job.workspace_id,
                correlation_id=correlation_id,
                details={"profile": job.profile.value, "maximum_requests": job.request_budget},
            )
            await self._stage(
                job,
                ScanStatus.VALIDATING_SCOPE,
                "Validating Scope",
                0.05,
                correlation_id,
            )
            if await self._is_cancelled(job, correlation_id):
                return
            await self._stage(job, ScanStatus.CRAWLING, "Crawling", 0.1, correlation_id)
            await self._crawl(job, policy, correlation_id)
            if job.status in {ScanStatus.CANCELLED, ScanStatus.BLOCKED, ScanStatus.FAILED}:
                return
            await self._stage(
                job,
                ScanStatus.FINGERPRINTING,
                "Fingerprinting",
                0.92,
                correlation_id,
            )
            await self._stage(
                job,
                ScanStatus.PASSIVE_ANALYSIS,
                "Passive Analysis",
                0.96,
                correlation_id,
            )
            job.status = ScanStatus.COMPLETED
            job.current_stage = "Completed"
            job.progress = 1
            job.finished_at = datetime.now(UTC)
            await self._event(
                job,
                "Passive scan completed without generating or executing mutation tests.",
                details={
                    "requests_used": job.requests_used,
                    "findings_count": job.findings_count,
                },
            )
            await self._audit.record(
                AuditEventType.SCAN_COMPLETED,
                resource_type="scan_job",
                resource_id=job.id,
                project_id=job.project_id,
                workspace_id=job.workspace_id,
                correlation_id=correlation_id,
                details={
                    "requests_used": job.requests_used,
                    "findings_count": job.findings_count,
                },
            )
            await self._session.commit()
        except asyncio.CancelledError:
            if job.status not in {
                ScanStatus.COMPLETED,
                ScanStatus.CANCELLED,
                ScanStatus.BLOCKED,
                ScanStatus.FAILED,
            }:
                job.cancellation_requested = True
                await self._is_cancelled(job, correlation_id)
            raise
        except ExecutionPolicyError as error:
            await self._fail(
                job,
                ScanStatus.BLOCKED,
                str(error),
                AuditEventType.SCAN_BLOCKED,
                correlation_id,
            )
        except DomainError as error:
            await self._fail(
                job,
                ScanStatus.FAILED,
                str(error),
                AuditEventType.SCAN_FAILED,
                correlation_id,
            )
        except Exception as error:
            await self._fail(
                job,
                ScanStatus.FAILED,
                "Passive scan failed; review the structured audit log.",
                AuditEventType.SCAN_FAILED,
                correlation_id,
            )
            await self._event(
                job,
                "Internal scanner error type recorded without response or credential data.",
                level="error",
                details={"error_type": type(error).__name__},
            )
            await self._session.commit()

    async def _crawl(
        self,
        job: ScanJob,
        policy: CrawlPolicy,
        correlation_id: str | None,
    ) -> None:
        queue: deque[tuple[str, int, str]] = deque([(job.target, 0, "seed")])
        endpoint_records: dict[tuple[str, str], ScanEndpoint] = {}
        parameter_keys: set[tuple[str, str, str]] = set()
        finding_keys: set[tuple[str, str]] = set()
        fingerprints: dict[str, TechnologyFingerprint] = {}
        inventory_limit = min(1000, max(20, policy.max_pages * 10))
        pages_fetched = 0
        last_request_at: float | None = None
        seed_origin = urlsplit(job.target)
        root = urlunsplit((seed_origin.scheme, seed_origin.netloc, "/", "", ""))
        for path in ("robots.txt", "sitemap.xml", "openapi.json", "swagger.json"):
            root_candidate = normalize_discovered_url(root, path)
            if root_candidate is not None:
                queue.append((root_candidate, 1, "well_known"))

        while queue and pages_fetched < policy.max_pages and job.requests_used < job.request_budget:
            if await self._is_cancelled(job, correlation_id):
                return
            url, depth, source = queue.popleft()
            key = ("GET", url)
            endpoint = endpoint_records.get(key)
            if endpoint is None:
                if len(endpoint_records) >= inventory_limit:
                    continue
                endpoint = await self._scans.add_endpoint(
                    ScanEndpoint(
                        scan_id=job.id,
                        url=url,
                        method="GET",
                        source=source,
                        depth=depth,
                    )
                )
                endpoint_records[key] = endpoint
                await self._add_parameters(job, query_parameters(url, source), parameter_keys)
                await self._session.commit()
            if endpoint.fetched or depth > policy.max_depth:
                continue
            if policy.respect_logout_routes and is_logout_route(url):
                await self._event(
                    job, "Logout-like route recorded but not requested.", details={"url": url}
                )
                await self._session.commit()
                continue
            await self._pace(last_request_at, policy)
            try:
                stored = await HttpRequestService(self._session, self._settings).create(
                    HttpRequestCreate(workspace_id=job.workspace_id, method="GET", url=url),
                    correlation_id,
                    source="scanner",
                )
                execution = RequestExecutionService(
                    self._session,
                    self._settings,
                    self._gate,
                    self._sender,
                    ScopeGuard(self._resolver),
                )
                remaining_requests = job.request_budget - job.requests_used
                maximum_request_count = min(5, remaining_requests)
                preview = await execution.preview(
                    stored.id,
                    correlation_id,
                    maximum_request_count=maximum_request_count,
                    max_response_bytes=policy.max_response_bytes,
                )
                result = await execution.execute(
                    stored.id,
                    RequestExecutionApproval(
                        confirmation_phrase="SEND UP TO 5 SAFE REQUESTS",
                        approval_token=preview.approval_token,
                        request_version=stored.version,
                    ),
                    correlation_id,
                    maximum_request_count=maximum_request_count,
                    max_response_bytes=policy.max_response_bytes,
                )
            except ExecutionPolicyError as error:
                await self._event(
                    job,
                    "Discovered endpoint was blocked by the shared execution policy.",
                    level="warning",
                    details={"url": url, "reason": str(error)},
                )
                await self._session.commit()
                if pages_fetched == 0 and url == job.target:
                    raise
                continue
            last_request_at = self._clock()
            pages_fetched += 1
            job.requests_used += result.request_count
            endpoint.fetched = True
            endpoint.status_code = result.response.status_code
            endpoint.content_type = result.response.normalized.content_type
            endpoint.http_request_id = stored.id
            endpoint.http_response_id = result.response.id
            response = result.response.normalized
            normalized_request = NormalizedRequest.model_validate(stored.normalized.model_dump())
            analysis_results = await self._analysis.analyze(
                normalized_request,
                response,
                AnalysisContext(
                    request_id=stored.id,
                    response_id=result.response.id,
                    network_execution_allowed=False,
                ),
            )
            await self._add_findings(job, url, analysis_results, finding_keys)
            for signal in fingerprint_response(response):
                fingerprints.setdefault(signal.name.lower(), signal)
            discovery = discover_document(url, response.body, response.content_type)
            endpoint.title = discovery.title
            await self._add_parameters(job, discovery.parameters, parameter_keys)
            for discovered_endpoint in discovery.endpoints[:inventory_limit]:
                await self._add_discovered_endpoint(
                    job,
                    discovered_endpoint,
                    depth + 1,
                    policy,
                    endpoint_records,
                    parameter_keys,
                    queue,
                    inventory_limit,
                )
            job.fingerprint_json = {
                "signals": [value.model_dump(mode="json") for value in fingerprints.values()]
            }
            job.progress = min(0.9, 0.1 + 0.8 * pages_fetched / max(1, policy.max_pages))
            await self._event(
                job,
                "Fetched and passively analyzed one endpoint.",
                details={
                    "url": url,
                    "status_code": response.status_code,
                    "requests_used": job.requests_used,
                },
            )
            await self._session.commit()
        if queue and job.requests_used >= job.request_budget:
            await self._event(
                job,
                "Scan stopped at the approved request budget.",
                level="warning",
                details={"request_budget": job.request_budget},
            )
            await self._session.commit()

    async def _add_parameters(
        self,
        job: ScanJob,
        parameters: list[DiscoveredParameter],
        seen: set[tuple[str, str, str]],
    ) -> None:
        for parameter in parameters[:1000]:
            key = (parameter.endpoint_url, parameter.name.lower(), parameter.location)
            if key in seen:
                continue
            seen.add(key)
            await self._scans.add_parameter(
                ScanParameter(
                    scan_id=job.id,
                    endpoint_url=parameter.endpoint_url,
                    name=parameter.name,
                    location=parameter.location,
                    sample_value=parameter.sample_value,
                    source=parameter.source,
                )
            )

    async def _add_findings(
        self,
        job: ScanJob,
        endpoint_url: str,
        results: list[AnalysisResult],
        seen: set[tuple[str, str]],
    ) -> None:
        for result in results:
            if result.status == VerificationStatus.NOT_TESTED:
                continue
            key = (endpoint_url, result.analyzer)
            if key in seen:
                continue
            seen.add(key)
            await self._scans.add_finding(
                ScanFinding(
                    scan_id=job.id,
                    endpoint_url=endpoint_url,
                    analyzer=result.analyzer,
                    category=result.category.value,
                    title=result.title,
                    summary=result.summary,
                    status=result.status.value,
                    severity=result.severity.value,
                    confidence=result.confidence,
                    evidence_json=[item.model_dump(mode="json") for item in result.evidence],
                    remediation_json=result.remediation,
                    limitations_json=result.limitations,
                )
            )
            job.findings_count += 1

    async def _add_discovered_endpoint(
        self,
        job: ScanJob,
        discovered: DiscoveredEndpoint,
        depth: int,
        policy: CrawlPolicy,
        endpoint_records: dict[tuple[str, str], ScanEndpoint],
        parameter_keys: set[tuple[str, str, str]],
        queue: deque[tuple[str, int, str]],
        inventory_limit: int,
    ) -> None:
        key = (discovered.method, discovered.url)
        if key not in endpoint_records and len(endpoint_records) < inventory_limit:
            record = await self._scans.add_endpoint(
                ScanEndpoint(
                    scan_id=job.id,
                    url=discovered.url,
                    method=discovered.method,
                    source=discovered.source,
                    depth=depth,
                )
            )
            endpoint_records[key] = record
            await self._add_parameters(
                job,
                query_parameters(discovered.url, discovered.source),
                parameter_keys,
            )
        if (
            discovered.crawlable
            and discovered.method == "GET"
            and "{" not in discovered.url
            and "}" not in discovered.url
            and depth <= policy.max_depth
            and same_crawl_origin(job.target, discovered.url, policy.include_subdomains)
            and not (policy.respect_logout_routes and is_logout_route(discovered.url))
        ):
            queue.append((discovered.url, depth, discovered.source))


async def run_scan_job(
    database: Database,
    settings: Settings,
    gate: RequestGate,
    sender: SingleHopSender,
    resolver: DnsResolver,
    scan_id: UUID,
    correlation_id: str | None,
) -> None:
    """Run one background job with a fresh transaction-scoped session."""

    async for session in database.session():
        await PassiveScanEngine(session, settings, gate, sender, resolver).run(
            scan_id,
            correlation_id,
        )

"""Execute only individually approved SAFE previews through the shared gateway."""

import asyncio
from collections import defaultdict
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.analyzers.models import TestCase
from webhacking_lab.api.schemas.resources import HttpRequestCreate, RequestExecutionApproval
from webhacking_lab.core.config import Settings
from webhacking_lab.core.rate_limit import RequestGate
from webhacking_lab.database.models import ScanEvent, ScanFinding, ScanJob, ScanTestCase
from webhacking_lab.database.repositories.audit import AuditRepository
from webhacking_lab.database.repositories.http import HttpRepository
from webhacking_lab.database.repositories.scans import ScanRepository
from webhacking_lab.database.session import Database
from webhacking_lab.domain.enums import (
    ActiveTestStatus,
    AuditEventType,
    RiskLevel,
    ScanStatus,
    VerificationStatus,
)
from webhacking_lab.domain.exceptions import ExecutionPolicyError
from webhacking_lab.http_client.client import SingleHopSender
from webhacking_lab.http_client.models import NormalizedRequest, NormalizedResponse
from webhacking_lab.http_client.request_normalizer import render_raw_request
from webhacking_lab.http_client.scope_guard import DnsResolver, ScopeGuard
from webhacking_lab.scanner.execution_policy import build_test_request
from webhacking_lab.scanner.models import ActiveTestPolicy, HttpExchange, ScanContext
from webhacking_lab.scanner.plugins import PLUGIN_BY_ID
from webhacking_lab.services.http_requests import HttpRequestService
from webhacking_lab.services.request_execution import RequestExecutionService


class SafeActiveScanEngine:
    """Own the approval-to-evidence transition for one SAFE scanner job."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        gate: RequestGate,
        sender: SingleHopSender,
        resolver: DnsResolver,
    ) -> None:
        self._session = session
        self._settings = settings
        self._gate = gate
        self._sender = sender
        self._resolver = resolver
        self._scans = ScanRepository(session)
        self._http = HttpRepository(session)
        self._audit = AuditRepository(session)

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

    async def run(self, scan_id: UUID, correlation_id: str | None = None) -> None:
        """Execute approved rows once, evaluate them, and record a terminal state."""

        job = await self._scans.get_job(scan_id)
        if job is None or job.status != ScanStatus.ACTIVE_TESTING:
            return
        approved = [
            value
            for value in await self._scans.list_test_cases(job.id)
            if value.status == ActiveTestStatus.APPROVED
        ]
        try:
            for test in approved:
                await self._session.refresh(job)
                if job.cancellation_requested:
                    job.status = ScanStatus.CANCELLED
                    job.current_stage = "Cancelled"
                    job.finished_at = datetime.now(UTC)
                    await self._event(
                        job,
                        "SAFE test execution cancelled before another request was queued.",
                        level="warning",
                    )
                    await self._session.commit()
                    return
                await self._execute_one(job, test, correlation_id)
            job.status = ScanStatus.VERIFYING
            job.current_stage = "Verifying"
            job.progress = 0.94
            await self._event(job, "Evaluating captured redacted response evidence.")
            await self._session.commit()
            await self._evaluate(job, correlation_id)
            job.status = ScanStatus.COMPLETED
            job.current_stage = "Completed"
            job.progress = 1
            job.finished_at = datetime.now(UTC)
            await self._event(
                job,
                "Approved SAFE tests completed; unapproved previews were never sent.",
                details={"requests_used": job.requests_used},
            )
            await self._audit.record(
                AuditEventType.SCAN_COMPLETED,
                resource_type="scan_job",
                resource_id=job.id,
                project_id=job.project_id,
                workspace_id=job.workspace_id,
                correlation_id=correlation_id,
                details={"requests_used": job.requests_used, "findings_count": job.findings_count},
            )
            await self._session.commit()
        except asyncio.CancelledError:
            job.cancellation_requested = True
            await self._session.commit()
            raise
        except Exception as error:
            job.status = ScanStatus.FAILED
            job.current_stage = "Failed"
            job.error_message = "SAFE test execution failed; review the audit log."
            job.finished_at = datetime.now(UTC)
            await self._event(
                job,
                job.error_message,
                level="error",
                details={"error_type": type(error).__name__},
            )
            await self._audit.record(
                AuditEventType.SCAN_FAILED,
                resource_type="scan_job",
                resource_id=job.id,
                project_id=job.project_id,
                workspace_id=job.workspace_id,
                correlation_id=correlation_id,
                details={"error_type": type(error).__name__},
            )
            await self._session.commit()

    async def _execute_one(
        self,
        job: ScanJob,
        test: ScanTestCase,
        correlation_id: str | None,
    ) -> None:
        baseline_request = await self._http.get_request(test.baseline_request_id)
        if baseline_request is None:
            raise ExecutionPolicyError("Baseline request is no longer available")
        test_case = TestCase(
            title=test.title,
            objective=test.objective,
            parameter=test.parameter,
            mutation_type=test.mutation_type,
            preview_value=test.preview_value,
            expected_signal=test.expected_signals_json,
            risk_level=RiskLevel(test.risk_level),
            requires_confirmation=test.requires_confirmation,
            max_requests=test.maximum_requests,
            destructive=test.destructive,
        )
        mutated = build_test_request(
            NormalizedRequest.model_validate(baseline_request.normalized_json),
            test_case,
            profile=job.profile,
        )
        if render_raw_request(mutated) != test.exact_request_preview:
            raise ExecutionPolicyError("Persisted exact request preview no longer matches policy")
        test.status = ActiveTestStatus.RUNNING
        await self._audit.record(
            AuditEventType.SCAN_TEST_STARTED,
            resource_type="scan_test_case",
            resource_id=test.id,
            project_id=job.project_id,
            workspace_id=job.workspace_id,
            correlation_id=correlation_id,
            details={"plugin_id": test.plugin_id, "method": mutated.method},
        )
        await self._session.commit()
        try:
            stored = await HttpRequestService(self._session, self._settings).create(
                HttpRequestCreate(
                    workspace_id=job.workspace_id,
                    method=mutated.method,
                    url=mutated.url,
                    headers=mutated.headers,
                ),
                correlation_id,
                source="scanner_test",
            )
            execution = RequestExecutionService(
                self._session,
                self._settings,
                self._gate,
                self._sender,
                ScopeGuard(self._resolver),
            )
            preview = await execution.preview(
                stored.id,
                correlation_id,
                maximum_request_count=1,
                max_response_bytes=self._settings.max_response_bytes,
                follow_redirects=False,
            )
            if preview.exact_request != test.exact_request_preview:
                raise ExecutionPolicyError(
                    "Gateway preview differs from the approved exact request"
                )
            result = await execution.execute(
                stored.id,
                RequestExecutionApproval(
                    confirmation_phrase="SEND UP TO 5 SAFE REQUESTS",
                    approval_token=preview.approval_token,
                    request_version=stored.version,
                ),
                correlation_id,
                maximum_request_count=1,
                max_response_bytes=self._settings.max_response_bytes,
                follow_redirects=False,
            )
            test.test_request_id = stored.id
            test.test_response_id = result.response.id
            test.status = ActiveTestStatus.COMPLETED
            test.completed_at = datetime.now(UTC)
            job.requests_used += result.request_count
            await self._audit.record(
                AuditEventType.SCAN_TEST_COMPLETED,
                resource_type="scan_test_case",
                resource_id=test.id,
                project_id=job.project_id,
                workspace_id=job.workspace_id,
                correlation_id=correlation_id,
                details={"status_code": result.response.status_code, "requests_sent": 1},
            )
        except ExecutionPolicyError as error:
            test.status = ActiveTestStatus.BLOCKED
            test.error_message = str(error)
            test.completed_at = datetime.now(UTC)
            await self._audit.record(
                AuditEventType.SCAN_TEST_BLOCKED,
                resource_type="scan_test_case",
                resource_id=test.id,
                project_id=job.project_id,
                workspace_id=job.workspace_id,
                correlation_id=correlation_id,
                details={"reason": str(error)},
            )
        await self._session.commit()

    @staticmethod
    def _exchange(
        request_id: UUID,
        response_id: UUID,
        request_json: dict[str, object],
        response_json: dict[str, object],
        mutation_type: str | None,
    ) -> HttpExchange:
        request = NormalizedRequest.model_validate(request_json)
        response = NormalizedResponse.model_validate(response_json)
        return HttpExchange(
            request_id=request_id,
            response_id=response_id,
            method=request.method,
            url=request.url,
            status_code=response.status_code,
            headers=[(item.name, item.value) for item in response.headers],
            body=response.body,
            elapsed_ms=response.elapsed_ms,
            mutation_type=mutation_type,
        )

    async def _evaluate(self, job: ScanJob, correlation_id: str | None) -> None:
        completed = [
            value
            for value in await self._scans.list_test_cases(job.id)
            if value.status == ActiveTestStatus.COMPLETED
            and value.test_request_id is not None
            and value.test_response_id is not None
        ]
        groups: dict[tuple[str, UUID, UUID], list[ScanTestCase]] = defaultdict(list)
        for test in completed:
            groups[(test.plugin_id, test.baseline_request_id, test.baseline_response_id)].append(
                test
            )
        context = ScanContext(
            scan_id=job.id,
            profile=job.profile,
            active_policy=ActiveTestPolicy.model_validate(
                job.metadata_json.get("active_test_policy", {})
            ),
        )
        for (plugin_id, baseline_request_id, baseline_response_id), tests in groups.items():
            plugin = PLUGIN_BY_ID.get(plugin_id)
            baseline_request = await self._http.get_request(baseline_request_id)
            baseline_response = await self._http.get_response(baseline_response_id)
            if plugin is None or baseline_request is None or baseline_response is None:
                continue
            baseline = self._exchange(
                baseline_request.id,
                baseline_response.id,
                baseline_request.normalized_json,
                baseline_response.normalized_json,
                None,
            )
            exchanges: list[HttpExchange] = []
            for test in tests:
                if test.test_request_id is None or test.test_response_id is None:
                    continue
                request = await self._http.get_request(test.test_request_id)
                response = await self._http.get_response(test.test_response_id)
                if request is not None and response is not None:
                    exchanges.append(
                        self._exchange(
                            request.id,
                            response.id,
                            request.normalized_json,
                            response.normalized_json,
                            test.mutation_type,
                        )
                    )
            try:
                async with asyncio.timeout(2):
                    result = await plugin.evaluate(baseline, exchanges, context)
            except TimeoutError:
                for test in tests:
                    test.status = ActiveTestStatus.INCONCLUSIVE
                    test.error_message = "Plugin evaluation exceeded the two-second CPU timeout"
                continue
            evidence = [item.model_dump(mode="json") for item in result.evidence]
            for test in tests:
                test.result_status = result.status.value
                test.confidence = result.confidence
                test.evidence_json = evidence
            if result.status not in {
                VerificationStatus.NOT_TESTED,
                VerificationStatus.FALSE_POSITIVE,
            }:
                await self._scans.add_finding(
                    ScanFinding(
                        scan_id=job.id,
                        endpoint_url=tests[0].endpoint_url,
                        analyzer=result.analyzer,
                        category=result.category.value,
                        title=result.title,
                        summary=result.summary,
                        status=result.status.value,
                        severity=result.severity.value,
                        confidence=result.confidence,
                        evidence_json=evidence,
                        remediation_json=result.remediation,
                        limitations_json=result.limitations,
                    )
                )
                job.findings_count += 1
        await self._session.commit()


async def run_approved_scan_tests(
    database: Database,
    settings: Settings,
    gate: RequestGate,
    sender: SingleHopSender,
    resolver: DnsResolver,
    scan_id: UUID,
    correlation_id: str | None,
) -> None:
    """Run approved tests with a fresh transaction-scoped session."""

    async for session in database.session():
        await SafeActiveScanEngine(session, settings, gate, sender, resolver).run(
            scan_id,
            correlation_id,
        )

"""Explicitly approved, scope-guarded request execution service."""

import ipaddress
from hashlib import sha256
from urllib.parse import urljoin, urlsplit
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.schemas.resources import (
    HttpResponseRead,
    RequestExecutionApproval,
    RequestExecutionPreview,
    RequestExecutionResult,
)
from webhacking_lab.core.config import Settings
from webhacking_lab.core.rate_limit import RequestGate
from webhacking_lab.database.models import HttpRequest, HttpResponse, ScopeRule, Workspace
from webhacking_lab.database.repositories.audit import AuditRepository
from webhacking_lab.database.repositories.http import HttpRepository
from webhacking_lab.database.repositories.projects import (
    ScopeRuleRepository,
    WorkspaceRepository,
)
from webhacking_lab.domain.enums import AuditEventType, WorkspaceMode
from webhacking_lab.domain.exceptions import (
    ConflictError,
    DomainError,
    EntityNotFoundError,
    ExecutionPolicyError,
)
from webhacking_lab.http_client.client import SingleHopSender, TransportResult
from webhacking_lab.http_client.models import (
    NormalizedRequest,
    RedirectHop,
    ScopeDecision,
    ScopeRuleSpec,
)
from webhacking_lab.http_client.request_normalizer import (
    content_type_and_charset,
    normalize_response,
    render_raw_request,
)
from webhacking_lab.http_client.scope_guard import ScopeGuard

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SAFE_REQUEST_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "access-control-request-method",
        "cache-control",
        "if-modified-since",
        "if-none-match",
        "origin",
        "referer",
        "user-agent",
    }
)
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REQUESTS_PER_APPROVAL = 5


def _is_local_target(hostname: str, mode: WorkspaceMode) -> bool:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return mode == WorkspaceMode.LOCAL_LAB and "." not in hostname


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


def _outbound_request(normalized: NormalizedRequest) -> tuple[NormalizedRequest, list[str]]:
    if normalized.method not in SAFE_METHODS:
        raise ExecutionPolicyError(
            "Controlled external execution currently permits only GET, HEAD, and OPTIONS"
        )
    if normalized.body:
        raise ExecutionPolicyError("Controlled external execution does not send request bodies")
    warnings: list[str] = []
    query = [item for item in normalized.query if not item.redacted]
    if len(query) != len(normalized.query):
        warnings.append("Sensitive query values were omitted instead of replayed")
    headers = [
        item
        for item in normalized.headers
        if not item.redacted and item.name.lower() in SAFE_REQUEST_HEADERS
    ]
    if len(headers) != len(normalized.headers):
        warnings.append("Cookies, credentials, and non-allowlisted headers were omitted")
    if not any(item.name.lower() == "user-agent" for item in headers):
        from webhacking_lab.http_client.models import NameValue

        headers.append(NameValue(name="User-Agent", value="WebHacking-Lab/0.1 controlled-request"))
    return (
        normalized.model_copy(
            update={"query": query, "headers": headers, "cookies": [], "body": ""}
        ),
        warnings,
    )


def _approval_token(
    request: HttpRequest,
    workspace: Workspace,
    exact_request: str,
    decision: ScopeDecision,
    maximum_request_count: int,
    max_response_bytes: int,
    follow_redirects: bool,
) -> str:
    material = "\n".join(
        (
            str(request.id),
            str(request.version),
            str(workspace.version),
            str(decision.matched_rule_id),
            str(maximum_request_count),
            str(max_response_bytes),
            str(follow_redirects),
            exact_request,
        )
    )
    return sha256(material.encode()).hexdigest()


def _decode_body(result: TransportResult) -> str:
    _, charset = content_type_and_charset(result.headers)
    try:
        return result.body.decode(charset, errors="replace")
    except LookupError:
        return result.body.decode("utf-8", errors="replace")


class RequestExecutionService:
    """Keep all network execution behind shared safety controls and auditing."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        gate: RequestGate,
        sender: SingleHopSender,
        guard: ScopeGuard | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._gate = gate
        self._sender = sender
        self._guard = guard or ScopeGuard()
        self._http = HttpRepository(session)
        self._workspaces = WorkspaceRepository(session)
        self._scopes = ScopeRuleRepository(session)
        self._audit = AuditRepository(session)

    def _check_server_policy(self) -> None:
        if self._settings.analysis_only or not self._settings.network_execution_enabled:
            raise ExecutionPolicyError("Network execution is disabled by the server safety policy")

    async def _load(self, request_id: UUID) -> tuple[HttpRequest, Workspace, list[ScopeRule]]:
        request = await self._http.get_request(request_id)
        if request is None:
            raise EntityNotFoundError("HTTP request was not found")
        workspace = await self._workspaces.get(request.workspace_id)
        if workspace is None:
            raise EntityNotFoundError("Workspace was not found")
        rules = await self._scopes.list_for_project(workspace.project_id)
        return request, workspace, rules

    async def _record_blocked(
        self,
        request: HttpRequest,
        workspace: Workspace,
        correlation_id: str | None,
        reason: str,
    ) -> None:
        await self._audit.record(
            AuditEventType.REQUEST_EXECUTION_BLOCKED,
            resource_type="http_request",
            resource_id=request.id,
            project_id=workspace.project_id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
            details={"reason": reason, "method": request.method},
        )
        await self._session.commit()

    async def _scope_decision(
        self,
        url: str,
        workspace: Workspace,
        rules: list[ScopeRule],
    ) -> tuple[ScopeDecision, ScopeRule]:
        decision = await self._guard.check(url, _scope_specs(rules))
        matched = next((rule for rule in rules if rule.id == decision.matched_rule_id), None)
        if not decision.allowed or matched is None:
            raise ExecutionPolicyError(f"Scope Guard blocked the request: {decision.reason}")
        if (
            not _is_local_target(decision.hostname or "", workspace.mode)
            and not matched.authorization_confirmed
        ):
            raise ExecutionPolicyError(
                "External targets require an explicitly authorized scope rule"
            )
        return decision, matched

    async def _build_preview(
        self,
        request: HttpRequest,
        workspace: Workspace,
        rules: list[ScopeRule],
        maximum_request_count: int,
        max_response_bytes: int,
        follow_redirects: bool,
    ) -> tuple[RequestExecutionPreview, NormalizedRequest]:
        self._check_server_policy()
        if not workspace.network_execution_enabled:
            raise ExecutionPolicyError("Network execution is disabled for this workspace")
        outbound, warnings = _outbound_request(
            NormalizedRequest.model_validate(request.normalized_json)
        )
        decision, _ = await self._scope_decision(outbound.url, workspace, rules)
        exact_request = render_raw_request(outbound)
        preview = RequestExecutionPreview(
            request_id=request.id,
            workspace_id=workspace.id,
            target_url=outbound.url,
            method=outbound.method,
            exact_request=exact_request,
            expected_impact=(
                "Read-only retrieval with no request body or stored credentials; redirects are "
                + (
                    "followed only after the same full safety check, up to "
                    if follow_redirects
                    else "not followed; "
                )
                + f"{maximum_request_count} total request(s), with at most "
                f"{max_response_bytes} response bytes per request."
            ),
            maximum_request_count=maximum_request_count,
            max_response_bytes=max_response_bytes,
            scope=decision,
            approval_token=_approval_token(
                request,
                workspace,
                exact_request,
                decision,
                maximum_request_count,
                max_response_bytes,
                follow_redirects,
            ),
            warnings=warnings,
        )
        return preview, outbound

    async def preview(
        self,
        request_id: UUID,
        correlation_id: str | None,
        *,
        maximum_request_count: int = MAX_REQUESTS_PER_APPROVAL,
        max_response_bytes: int | None = None,
        follow_redirects: bool = True,
    ) -> RequestExecutionPreview:
        """Return and audit the exact initial request plus maximum redirect budget."""

        if not 1 <= maximum_request_count <= MAX_REQUESTS_PER_APPROVAL:
            raise ExecutionPolicyError("Approval request count must be between one and five")
        requested_limit = (
            self._settings.max_response_bytes if max_response_bytes is None else max_response_bytes
        )
        if requested_limit < 1:
            raise ExecutionPolicyError("Response size limit must be positive")
        response_limit = min(self._settings.max_response_bytes, requested_limit)
        request, workspace, rules = await self._load(request_id)
        try:
            preview, _ = await self._build_preview(
                request,
                workspace,
                rules,
                maximum_request_count,
                response_limit,
                follow_redirects,
            )
        except ExecutionPolicyError as error:
            await self._record_blocked(request, workspace, correlation_id, str(error))
            raise
        await self._audit.record(
            AuditEventType.REQUEST_EXECUTION_PREVIEWED,
            resource_type="http_request",
            resource_id=request.id,
            project_id=workspace.project_id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
            details={"method": preview.method, "hostname": preview.scope.hostname or ""},
        )
        return preview

    async def execute(
        self,
        request_id: UUID,
        approval: RequestExecutionApproval,
        correlation_id: str | None,
        *,
        maximum_request_count: int = MAX_REQUESTS_PER_APPROVAL,
        max_response_bytes: int | None = None,
        follow_redirects: bool = True,
    ) -> RequestExecutionResult:
        """Execute the approved request chain, rechecking every redirect before use."""

        if not 1 <= maximum_request_count <= MAX_REQUESTS_PER_APPROVAL:
            raise ExecutionPolicyError("Approval request count must be between one and five")
        requested_limit = (
            self._settings.max_response_bytes if max_response_bytes is None else max_response_bytes
        )
        if requested_limit < 1:
            raise ExecutionPolicyError("Response size limit must be positive")
        response_limit = min(self._settings.max_response_bytes, requested_limit)
        request, workspace, rules = await self._load(request_id)
        try:
            preview, outbound = await self._build_preview(
                request,
                workspace,
                rules,
                maximum_request_count,
                response_limit,
                follow_redirects,
            )
            if request.version != approval.request_version:
                raise ConflictError("Request was modified after the approval preview")
            if preview.approval_token != approval.approval_token:
                raise ConflictError("Approval preview is stale; review the exact request again")
        except (ExecutionPolicyError, ConflictError) as error:
            await self._record_blocked(request, workspace, correlation_id, str(error))
            raise

        await self._audit.record(
            AuditEventType.REQUEST_EXECUTION_STARTED,
            resource_type="http_request",
            resource_id=request.id,
            project_id=workspace.project_id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
            details={
                "method": outbound.method,
                "hostname": outbound.host,
                "maximum_requests": maximum_request_count,
            },
        )
        await self._session.commit()

        current_url = outbound.url
        current_method = outbound.method
        redirect_history: list[RedirectHop] = []
        final_result: TransportResult | None = None
        requests_sent = 0
        try:
            for request_number in range(maximum_request_count):
                decision, rule = await self._scope_decision(current_url, workspace, rules)
                parsed_target = urlsplit(current_url)
                target_key = f"{parsed_target.scheme}://{parsed_target.netloc}"
                async with self._gate.slot(
                    target_key,
                    global_per_minute=self._settings.global_requests_per_minute,
                    target_per_minute=rule.max_requests_per_minute,
                    max_concurrency=rule.max_concurrency,
                ):
                    if not await self._workspaces.consume_request_budget(workspace.id):
                        raise ExecutionPolicyError("Workspace request budget is exhausted")
                    await self._session.commit()
                    final_result = await self._sender.send(
                        method=current_method,
                        url=current_url,
                        headers=[(item.name, item.value) for item in outbound.headers],
                        resolved_ips=decision.resolved_ips,
                        expected_hostname=decision.hostname or "",
                        max_response_bytes=response_limit,
                    )
                requests_sent += 1
                location = next(
                    (value for name, value in final_result.headers if name.lower() == "location"),
                    None,
                )
                if final_result.status_code not in REDIRECT_STATUSES or location is None:
                    break
                if not follow_redirects:
                    break
                next_url = urljoin(current_url, location)
                next_decision, _ = await self._scope_decision(next_url, workspace, rules)
                if current_url.startswith("https://") and next_url.startswith("http://"):
                    raise ExecutionPolicyError("HTTPS-to-HTTP redirect downgrade is blocked")
                redirect_history.append(
                    RedirectHop(
                        status_code=final_result.status_code,
                        url=current_url,
                        location=next_decision.normalized_url,
                    )
                )
                if request_number + 1 == maximum_request_count:
                    break
                current_url = next_url
                if final_result.status_code == 303:
                    current_method = "GET"
        except DomainError as error:
            await self._record_blocked(request, workspace, correlation_id, str(error))
            raise

        if final_result is None:
            raise ExecutionPolicyError("No approved request was sent")
        normalized_response = normalize_response(
            status_code=final_result.status_code,
            reason=final_result.reason,
            headers=final_result.headers,
            body=_decode_body(final_result),
            elapsed_ms=final_result.elapsed_ms,
            redirect_history=redirect_history,
            max_body_bytes=response_limit,
        )
        response_model = await self._http.add_response(
            HttpResponse(
                request_id=request.id,
                status_code=normalized_response.status_code,
                normalized_json=normalized_response.model_dump(mode="json"),
                body_size=len(final_result.body),
                elapsed_ms=normalized_response.elapsed_ms,
            )
        )
        await self._audit.record(
            AuditEventType.REQUEST_EXECUTION_COMPLETED,
            resource_type="http_response",
            resource_id=response_model.id,
            project_id=workspace.project_id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
            details={
                "status_code": normalized_response.status_code,
                "response_bytes": len(final_result.body),
                "requests_sent": requests_sent,
                "redirects": len(redirect_history),
            },
        )
        await self._session.refresh(workspace)
        return RequestExecutionResult(
            preview=preview,
            response=HttpResponseRead(
                id=response_model.id,
                request_id=request.id,
                status_code=response_model.status_code,
                normalized=normalized_response,
                body_size=response_model.body_size,
                elapsed_ms=response_model.elapsed_ms,
                created_at=response_model.created_at,
            ),
            requests_used=workspace.requests_used,
            request_budget=workspace.request_budget,
            request_count=requests_sent,
        )

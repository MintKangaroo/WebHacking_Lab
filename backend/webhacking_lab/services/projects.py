"""Project aggregate and scope policy services."""

import ipaddress
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.api.schemas.resources import (
    ProjectCreate,
    ProjectDetail,
    ProjectPatch,
    ProjectSummary,
    ScopeRuleCreate,
    ScopeRuleRead,
    WorkspaceCreate,
    WorkspaceExecutionApproval,
    WorkspaceExecutionDisable,
    WorkspacePatch,
    WorkspaceRead,
)
from webhacking_lab.core.config import Settings
from webhacking_lab.database.models import Project, ScopeRule, Workspace
from webhacking_lab.database.repositories.audit import AuditRepository
from webhacking_lab.database.repositories.projects import (
    ProjectRepository,
    ScopeRuleRepository,
    WorkspaceRepository,
)
from webhacking_lab.domain.enums import AnalysisMode, AuditEventType, WorkspaceMode
from webhacking_lab.domain.exceptions import (
    ConflictError,
    EntityNotFoundError,
    ExecutionPolicyError,
    ScopeValidationError,
)
from webhacking_lab.http_client.models import ScopeDecision, ScopeRuleSpec
from webhacking_lab.http_client.request_normalizer import normalize_hostname
from webhacking_lab.http_client.scope_guard import DnsResolver, ScopeGuard


def workspace_read(workspace: Workspace) -> WorkspaceRead:
    return WorkspaceRead.model_validate(workspace)


def scope_read(rule: ScopeRule) -> ScopeRuleRead:
    return ScopeRuleRead.model_validate(rule)


def project_summary(project: Project) -> ProjectSummary:
    return ProjectSummary(
        id=project.id,
        name=project.name,
        description=project.description,
        mode=project.mode,
        version=project.version,
        workspace_count=len(project.workspaces),
        scope_rule_count=len(project.scope_rules),
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


def project_detail(project: Project) -> ProjectDetail:
    summary = project_summary(project)
    return ProjectDetail(
        **summary.model_dump(),
        workspaces=[workspace_read(item) for item in project.workspaces if item.deleted_at is None],
        scope_rules=[scope_read(item) for item in project.scope_rules if item.deleted_at is None],
    )


class ProjectService:
    """Manage projects and their safe-by-default initial workspace."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._projects = ProjectRepository(session)
        self._workspaces = WorkspaceRepository(session)
        self._scopes = ScopeRuleRepository(session)
        self._audit = AuditRepository(session)

    async def create(self, data: ProjectCreate, correlation_id: str | None) -> ProjectDetail:
        project = await self._projects.add(
            Project(name=data.name.strip(), description=data.description.strip(), mode=data.mode)
        )
        await self._workspaces.add(
            Workspace(
                project_id=project.id,
                name="Primary Workspace",
                mode=data.mode,
                analysis_mode=AnalysisMode.MANUAL_HTTP,
                network_execution_enabled=False,
                request_budget=100,
            )
        )
        for hostname in ("localhost", "127.0.0.1", "::1"):
            for scheme in ("http", "https"):
                await self._scopes.add(
                    ScopeRule(
                        project_id=project.id,
                        scheme=scheme,
                        hostname=hostname,
                        path_prefix="/",
                        authorization_notes="Built-in loopback scope",
                    )
                )
        await self._audit.record(
            AuditEventType.PROJECT_CREATED,
            resource_type="project",
            resource_id=project.id,
            project_id=project.id,
            correlation_id=correlation_id,
            details={"name": project.name, "mode": project.mode.value},
        )
        loaded = await self._projects.get(project.id)
        if loaded is None:
            raise EntityNotFoundError("Created project could not be reloaded")
        return project_detail(loaded)

    async def list(self) -> list[ProjectSummary]:
        return [project_summary(project) for project in await self._projects.list()]

    async def get(self, project_id: UUID) -> ProjectDetail:
        project = await self._projects.get(project_id)
        if project is None:
            raise EntityNotFoundError("Project was not found")
        return project_detail(project)

    async def update(
        self,
        project_id: UUID,
        data: ProjectPatch,
        correlation_id: str | None,
    ) -> ProjectDetail:
        project = await self._projects.get(project_id)
        if project is None:
            raise EntityNotFoundError("Project was not found")
        if project.version != data.version:
            raise ConflictError("Project was modified by another operation")
        changes = data.model_dump(exclude={"version"}, exclude_none=True)
        for field, value in changes.items():
            setattr(project, field, value.strip() if isinstance(value, str) else value)
        project.version += 1
        await self._audit.record(
            AuditEventType.PROJECT_UPDATED,
            resource_type="project",
            resource_id=project.id,
            project_id=project.id,
            correlation_id=correlation_id,
            details={"changed_fields": sorted(changes)},
        )
        await self._session.refresh(project, attribute_names=["updated_at"])
        return project_detail(project)

    async def delete(self, project_id: UUID, correlation_id: str | None) -> None:
        project = await self._projects.get(project_id)
        if project is None:
            raise EntityNotFoundError("Project was not found")
        project.deleted_at = datetime.now(UTC)
        project.version += 1
        await self._audit.record(
            AuditEventType.PROJECT_DELETED,
            resource_type="project",
            resource_id=project.id,
            project_id=project.id,
            correlation_id=correlation_id,
        )


class WorkspaceService:
    """Manage workspaces and their explicit network-execution state."""

    def __init__(self, session: AsyncSession, settings: Settings | None = None) -> None:
        self._session = session
        self._projects = ProjectRepository(session)
        self._workspaces = WorkspaceRepository(session)
        self._audit = AuditRepository(session)
        self._settings = settings

    async def create(self, data: WorkspaceCreate, correlation_id: str | None) -> WorkspaceRead:
        project = await self._projects.get(data.project_id)
        if project is None:
            raise EntityNotFoundError("Project was not found")
        workspace = await self._workspaces.add(
            Workspace(
                project_id=project.id,
                name=data.name.strip(),
                mode=data.mode or project.mode,
                analysis_mode=data.analysis_mode,
                request_budget=data.request_budget,
                network_execution_enabled=False,
            )
        )
        await self._audit.record(
            AuditEventType.WORKSPACE_CREATED,
            resource_type="workspace",
            resource_id=workspace.id,
            project_id=project.id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
        )
        return workspace_read(workspace)

    async def get(self, workspace_id: UUID) -> WorkspaceRead:
        workspace = await self._workspaces.get(workspace_id)
        if workspace is None:
            raise EntityNotFoundError("Workspace was not found")
        return workspace_read(workspace)

    async def update(
        self,
        workspace_id: UUID,
        data: WorkspacePatch,
        correlation_id: str | None,
    ) -> WorkspaceRead:
        workspace = await self._workspaces.get(workspace_id)
        if workspace is None:
            raise EntityNotFoundError("Workspace was not found")
        if workspace.version != data.version:
            raise ConflictError("Workspace was modified by another operation")
        changes = data.model_dump(exclude={"version"}, exclude_none=True)
        for field, value in changes.items():
            setattr(workspace, field, value.strip() if isinstance(value, str) else value)
        workspace.version += 1
        await self._audit.record(
            AuditEventType.WORKSPACE_UPDATED,
            resource_type="workspace",
            resource_id=workspace.id,
            project_id=workspace.project_id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
            details={"changed_fields": sorted(changes)},
        )
        await self._session.refresh(workspace, attribute_names=["updated_at"])
        return workspace_read(workspace)

    async def enable_execution(
        self,
        workspace_id: UUID,
        data: WorkspaceExecutionApproval,
        correlation_id: str | None,
    ) -> WorkspaceRead:
        """Enable controlled execution only when the process policy also allows it."""

        if (
            self._settings is None
            or self._settings.analysis_only
            or not self._settings.network_execution_enabled
        ):
            raise ExecutionPolicyError(
                "Network execution is disabled by the server. Set the two safety environment "
                "switches explicitly before enabling a workspace."
            )
        workspace = await self._workspaces.get(workspace_id)
        if workspace is None:
            raise EntityNotFoundError("Workspace was not found")
        if workspace.version != data.version:
            raise ConflictError("Workspace was modified by another operation")
        workspace.network_execution_enabled = True
        workspace.version += 1
        await self._audit.record(
            AuditEventType.WORKSPACE_EXECUTION_ENABLED,
            resource_type="workspace",
            resource_id=workspace.id,
            project_id=workspace.project_id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
            details={"expected_use": data.expected_use.strip()},
        )
        await self._session.refresh(workspace, attribute_names=["updated_at"])
        return workspace_read(workspace)

    async def disable_execution(
        self,
        workspace_id: UUID,
        data: WorkspaceExecutionDisable,
        correlation_id: str | None,
    ) -> WorkspaceRead:
        """Immediately return a workspace to analysis-only behavior."""

        workspace = await self._workspaces.get(workspace_id)
        if workspace is None:
            raise EntityNotFoundError("Workspace was not found")
        if workspace.version != data.version:
            raise ConflictError("Workspace was modified by another operation")
        workspace.network_execution_enabled = False
        workspace.version += 1
        await self._audit.record(
            AuditEventType.WORKSPACE_EXECUTION_DISABLED,
            resource_type="workspace",
            resource_id=workspace.id,
            project_id=workspace.project_id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
        )
        await self._session.refresh(workspace, attribute_names=["updated_at"])
        return workspace_read(workspace)


def _is_local_registration(hostname: str, mode: WorkspaceMode) -> bool:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return mode == WorkspaceMode.LOCAL_LAB and "." not in hostname


class ScopeService:
    """Register and preview project scope without performing HTTP requests."""

    def __init__(self, session: AsyncSession, resolver: DnsResolver | None = None) -> None:
        self._projects = ProjectRepository(session)
        self._scopes = ScopeRuleRepository(session)
        self._audit = AuditRepository(session)
        self._guard = ScopeGuard(resolver)

    async def add(
        self,
        project_id: UUID,
        data: ScopeRuleCreate,
        correlation_id: str | None,
    ) -> ScopeRuleRead:
        project = await self._projects.get(project_id)
        if project is None:
            raise EntityNotFoundError("Project was not found")
        hostname = normalize_hostname(data.hostname)
        local = _is_local_registration(hostname, project.mode)
        if not local and (
            not data.authorization_confirmed or len(data.authorization_notes.strip()) < 10
        ):
            raise ScopeValidationError(
                "External scope requires authorization confirmation and a scope description"
            )
        existing = await self._scopes.list_for_project(project_id)
        if any(
            rule.scheme == data.scheme
            and rule.hostname == hostname
            and rule.port == data.port
            and rule.path_prefix == data.path_prefix
            for rule in existing
        ):
            raise ConflictError("An equivalent scope rule already exists")
        rule = await self._scopes.add(
            ScopeRule(
                project_id=project_id,
                scheme=data.scheme,
                hostname=hostname,
                port=data.port,
                path_prefix=data.path_prefix,
                allow_subdomains=data.allow_subdomains,
                max_requests_per_minute=data.max_requests_per_minute,
                max_concurrency=data.max_concurrency,
                authorization_confirmed=data.authorization_confirmed,
                authorization_notes=data.authorization_notes.strip(),
            )
        )
        await self._audit.record(
            AuditEventType.SCOPE_RULE_CREATED,
            resource_type="scope_rule",
            resource_id=rule.id,
            project_id=project_id,
            correlation_id=correlation_id,
            details={"hostname": hostname, "scheme": data.scheme, "path_prefix": data.path_prefix},
        )
        return scope_read(rule)

    async def list(self, project_id: UUID) -> list[ScopeRuleRead]:
        if await self._projects.get(project_id) is None:
            raise EntityNotFoundError("Project was not found")
        return [scope_read(rule) for rule in await self._scopes.list_for_project(project_id)]

    async def check(
        self,
        project_id: UUID,
        url: str,
        correlation_id: str | None,
    ) -> ScopeDecision:
        if await self._projects.get(project_id) is None:
            raise EntityNotFoundError("Project was not found")
        rules = await self._scopes.list_for_project(project_id)
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
        decision = await self._guard.check(url, specs)
        await self._audit.record(
            AuditEventType.SCOPE_CHECKED,
            resource_type="scope_check",
            resource_id=decision.matched_rule_id,
            project_id=project_id,
            correlation_id=correlation_id,
            details={
                "allowed": decision.allowed,
                "code": decision.code,
                "hostname": decision.hostname or "",
            },
        )
        return decision

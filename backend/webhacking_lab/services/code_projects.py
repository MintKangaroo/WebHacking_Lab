"""Source upload, indexing, redacted viewing, and route inventory orchestration."""

import asyncio
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.core.config import Settings
from webhacking_lab.database.models import (
    CodeFile,
    CodeProject,
    StaticFindingRecord,
    StaticRouteRecord,
)
from webhacking_lab.database.repositories.audit import AuditRepository
from webhacking_lab.database.repositories.code_projects import CodeProjectRepository
from webhacking_lab.database.repositories.projects import ProjectRepository
from webhacking_lab.domain.enums import AuditEventType, CodeProjectStatus
from webhacking_lab.domain.exceptions import (
    AuthorizationRequiredError,
    ConflictError,
    EntityNotFoundError,
    UploadLimitError,
    UploadValidationError,
)
from webhacking_lab.static_analysis.archive import SecureUploadStore
from webhacking_lab.static_analysis.file_index import index_source_tree
from webhacking_lab.static_analysis.models import (
    AuthenticationInfo,
    CodeAnalysisRead,
    CodeFileContentRead,
    CodeFileRead,
    CodeProjectCreate,
    CodeProjectRead,
    CodeUploadRead,
    IndexedFile,
    StaticCodeFinding,
    StaticDataFlow,
    StaticFlowEdge,
    StaticFlowStep,
    StaticParameter,
    StaticRemediation,
    StaticRoute,
    UploadPolicy,
)
from webhacking_lab.static_analysis.project_detector import detect_project
from webhacking_lab.static_analysis.route_extractor import extract_routes
from webhacking_lab.static_analysis.secret_scanner import redact_source
from webhacking_lab.static_analysis.taint_engine import analyze_static_data_flows

MAX_EDITOR_BYTES = 500_000


def _upload_policy(settings: Settings) -> UploadPolicy:
    return UploadPolicy(
        max_archive_bytes=settings.max_code_archive_bytes,
        max_extracted_bytes=settings.max_code_extracted_bytes,
        max_files=settings.max_code_files,
        max_single_file_bytes=settings.max_code_single_file_bytes,
        max_archive_depth=settings.max_code_archive_depth,
    )


def _project_read(project: CodeProject) -> CodeProjectRead:
    return CodeProjectRead(
        id=project.id,
        project_id=project.project_id,
        name=project.name,
        description=project.description,
        authorization_confirmed=project.authorization_confirmed,
        authorization_notes=project.authorization_notes,
        status=project.status,
        languages=project.languages_json,
        frameworks=project.frameworks_json,
        dependency_files=project.dependency_files_json,
        warnings=project.warnings_json,
        total_files=project.total_files,
        total_bytes=project.total_bytes,
        secret_findings_count=project.secret_findings_count,
        analyzed_at=project.analyzed_at,
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


def _file_read(file: CodeFile) -> CodeFileRead:
    return CodeFileRead(
        id=file.id,
        relative_path=file.relative_path,
        language=file.language,
        size_bytes=file.size_bytes,
        sha256=file.sha256,
        secret_findings_count=file.secret_findings_count,
        warning_codes=file.warning_codes_json,
        route_count=file.route_count,
    )


def _route_read(route: StaticRouteRecord, file_path: str) -> StaticRoute:
    return StaticRoute(
        id=route.id,
        code_file_id=route.code_file_id,
        framework=route.framework,
        methods=route.methods_json,
        path=route.path,
        handler_name=route.handler_name,
        file_path=file_path,
        line_start=route.line_start,
        line_end=route.line_end,
        parameters=[StaticParameter.model_validate(value) for value in route.parameters_json],
        authentication=AuthenticationInfo.model_validate(route.authentication_json),
        findings=route.findings_json,
    )


def _finding_read(
    finding: StaticFindingRecord,
    file_path: str,
    route_path: str | None,
) -> StaticCodeFinding:
    return StaticCodeFinding(
        id=finding.id,
        code_project_id=finding.code_project_id,
        code_file_id=finding.code_file_id,
        static_route_id=finding.static_route_id,
        file_path=file_path,
        route=route_path,
        route_handler=finding.route_handler,
        category=finding.category,
        title=finding.title,
        status=finding.status,
        severity=finding.severity,
        confidence=finding.confidence,
        source_label=finding.source_label,
        sink_label=finding.sink_label,
        parameter=finding.parameter,
        source_line=finding.source_line,
        sink_line=finding.sink_line,
        sanitizers=finding.sanitizers_json,
        evidence=finding.evidence_json,
        remediation=StaticRemediation.model_validate(finding.remediation_json),
        limitations=finding.limitations_json,
    )


def _flow_read(finding: StaticFindingRecord) -> StaticDataFlow:
    nodes = [StaticFlowStep.model_validate(value) for value in finding.flow_steps_json]
    edges = [
        StaticFlowEdge(
            id=f"edge-{index}",
            source=source.id,
            target=target.id,
            label="flows to",
        )
        for index, (source, target) in enumerate(pairwise(nodes))
    ]
    return StaticDataFlow(finding_id=finding.id, nodes=nodes, edges=edges)


class CodeProjectService:
    """Apply one policy to source artifacts from upload through display."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._projects = ProjectRepository(session)
        self._codes = CodeProjectRepository(session)
        self._audit = AuditRepository(session)
        self._policy = _upload_policy(settings)
        self._store = SecureUploadStore(Path(settings.code_upload_root), self._policy)

    async def create(
        self,
        data: CodeProjectCreate,
        correlation_id: str | None,
    ) -> CodeProjectRead:
        """Create metadata only; no path supplied by the caller becomes a storage path."""

        if await self._projects.get(data.project_id) is None:
            raise EntityNotFoundError("Parent project was not found")
        project = await self._codes.add(
            CodeProject(
                project_id=data.project_id,
                name=data.name.strip(),
                description=data.description.strip(),
                authorization_confirmed=True,
                authorization_notes=data.authorization_notes.strip(),
                status=CodeProjectStatus.EMPTY,
                storage_key=str(uuid4()),
            )
        )
        await self._audit.record(
            AuditEventType.CODE_PROJECT_CREATED,
            resource_type="code_project",
            resource_id=project.id,
            project_id=project.project_id,
            correlation_id=correlation_id,
            details={"name": project.name, "authorization_notes": project.authorization_notes},
        )
        await self._session.commit()
        return _project_read(project)

    async def list_projects(self, project_id: UUID | None = None) -> list[CodeProjectRead]:
        return [_project_read(value) for value in await self._codes.list_projects(project_id)]

    async def get(self, code_project_id: UUID) -> CodeProjectRead:
        project = await self._require_project(code_project_id)
        return _project_read(project)

    async def upload(
        self,
        code_project_id: UUID,
        files: list[UploadFile],
        correlation_id: str | None,
    ) -> CodeUploadRead:
        """Stage untrusted files, index inert text, then commit artifact metadata."""

        project = await self._require_project(code_project_id)
        if not project.authorization_confirmed:
            await self._audit.record(
                AuditEventType.CODE_PROJECT_UPLOAD_BLOCKED,
                resource_type="code_project",
                resource_id=project.id,
                project_id=project.project_id,
                correlation_id=correlation_id,
                details={"reason": "authorization_required", "code_executed": False},
            )
            await self._session.commit()
            raise AuthorizationRequiredError(
                "Source authorization must be reconfirmed before uploading files"
            )
        if project.status != CodeProjectStatus.EMPTY or project.files:
            raise ConflictError("This code project already contains an immutable upload")
        try:
            root = await self._store.ingest(files, project.storage_key)
            indexed, index_warnings = await asyncio.to_thread(
                index_source_tree,
                root,
                self._policy,
            )
            if not indexed:
                raise UploadValidationError("No supported source or configuration files were found")
            detection = await asyncio.to_thread(detect_project, root, indexed)
            records = [
                await self._codes.add_file(
                    CodeFile(
                        code_project_id=project.id,
                        relative_path=entry.relative_path,
                        language=entry.language,
                        size_bytes=entry.size_bytes,
                        sha256=entry.sha256,
                        secret_findings_count=len(entry.secret_findings),
                        warning_codes_json=entry.warning_codes,
                    )
                )
                for entry in indexed
            ]
            project.status = CodeProjectStatus.INDEXED
            project.languages_json = detection.languages
            project.frameworks_json = detection.frameworks
            project.dependency_files_json = detection.dependency_files
            project.warnings_json = sorted({*index_warnings, *detection.warnings})[:100]
            project.total_files = len(indexed)
            project.total_bytes = sum(item.size_bytes for item in indexed)
            project.secret_findings_count = sum(len(item.secret_findings) for item in indexed)
            project.version += 1
            await self._audit.record(
                AuditEventType.CODE_PROJECT_UPLOAD_ACCEPTED,
                resource_type="code_project",
                resource_id=project.id,
                project_id=project.project_id,
                correlation_id=correlation_id,
                details={
                    "file_count": project.total_files,
                    "total_bytes": project.total_bytes,
                    "secret_findings": project.secret_findings_count,
                    "code_executed": False,
                },
            )
            await self._session.commit()
            await self._session.refresh(project)
            return CodeUploadRead(
                project=_project_read(project),
                files=[_file_read(value) for value in records],
                policy=self._policy,
            )
        except (UploadValidationError, UploadLimitError) as error:
            self._store.delete(project.storage_key)
            await self._session.rollback()
            project = await self._require_project(code_project_id)
            await self._audit.record(
                AuditEventType.CODE_PROJECT_UPLOAD_BLOCKED,
                resource_type="code_project",
                resource_id=project.id,
                project_id=project.project_id,
                correlation_id=correlation_id,
                details={"reason": str(error), "code_executed": False},
            )
            await self._session.commit()
            raise
        except Exception:
            self._store.delete(project.storage_key)
            await self._session.rollback()
            raise

    async def files(self, code_project_id: UUID) -> list[CodeFileRead]:
        await self._require_project(code_project_id)
        return [_file_read(value) for value in await self._codes.list_files(code_project_id)]

    async def file_content(
        self,
        code_project_id: UUID,
        file_id: UUID,
    ) -> CodeFileContentRead:
        project = await self._require_project(code_project_id)
        file = await self._codes.get_file(file_id)
        if file is None or file.code_project_id != project.id:
            raise EntityNotFoundError("Code file was not found")
        root = self._store.resolve(project.storage_key)
        path = (root / file.relative_path).resolve()
        if not path.is_relative_to(root) or not path.is_file() or path.is_symlink():
            raise UploadValidationError("Indexed source path failed its storage check")
        raw = await asyncio.to_thread(path.read_bytes)
        truncated = len(raw) > MAX_EDITOR_BYTES
        content = raw[:MAX_EDITOR_BYTES].decode("utf-8", errors="replace")
        rendered, redacted = redact_source(content)
        return CodeFileContentRead(
            **_file_read(file).model_dump(),
            content=rendered,
            redacted=redacted,
            truncated=truncated,
        )

    async def analyze(
        self,
        code_project_id: UUID,
        correlation_id: str | None,
    ) -> CodeAnalysisRead:
        """Extract routes and bounded source-to-sink traces without running code."""

        project = await self._require_project(code_project_id)
        if project.status == CodeProjectStatus.EMPTY:
            raise ConflictError("Upload source files before analysis")
        project.status = CodeProjectStatus.ANALYZING
        await self._session.commit()
        try:
            records = await self._codes.list_files(project.id)
            indexed = [
                IndexedFile(
                    relative_path=value.relative_path,
                    language=value.language,
                    size_bytes=value.size_bytes,
                    sha256=value.sha256,
                    secret_findings=[],
                    warning_codes=value.warning_codes_json,
                )
                for value in records
            ]
            root = self._store.resolve(project.storage_key)
            extraction = await asyncio.to_thread(
                extract_routes,
                root,
                indexed,
                project.frameworks_json,
            )
            taint = await asyncio.to_thread(
                analyze_static_data_flows,
                root,
                indexed,
                extraction.routes,
            )
            by_path = {value.relative_path: value for value in records}
            for value in records:
                value.route_count = 0
            route_records: list[StaticRouteRecord] = []
            for extracted_route in extraction.routes:
                code_file = by_path[extracted_route.file_path]
                code_file.route_count += 1
                route_records.append(
                    StaticRouteRecord(
                        code_project_id=project.id,
                        code_file_id=code_file.id,
                        framework=extracted_route.framework,
                        methods_json=extracted_route.methods,
                        path=extracted_route.path,
                        handler_name=extracted_route.handler_name,
                        line_start=extracted_route.line_start,
                        line_end=extracted_route.line_end,
                        parameters_json=[
                            value.model_dump(mode="json") for value in extracted_route.parameters
                        ],
                        authentication_json=extracted_route.authentication.model_dump(mode="json"),
                        findings_json=extracted_route.findings,
                    )
                )
            await self._codes.replace_routes(project.id, route_records)
            route_by_handler = {
                (value.code_file_id, value.handler_name): value for value in route_records
            }
            finding_records: list[StaticFindingRecord] = []
            for extracted_finding in taint.findings:
                finding_file = by_path.get(extracted_finding.file_path)
                if finding_file is None:
                    continue
                static_route = route_by_handler.get(
                    (finding_file.id, extracted_finding.route_handler or "")
                )
                finding_records.append(
                    StaticFindingRecord(
                        code_project_id=project.id,
                        code_file_id=finding_file.id,
                        static_route_id=static_route.id if static_route is not None else None,
                        category=extracted_finding.category.value,
                        title=extracted_finding.title,
                        status=extracted_finding.status.value,
                        severity=extracted_finding.severity.value,
                        confidence=extracted_finding.confidence,
                        route_handler=extracted_finding.route_handler,
                        source_label=extracted_finding.source_label,
                        sink_label=extracted_finding.sink_label,
                        parameter=extracted_finding.parameter,
                        source_line=extracted_finding.source_line,
                        sink_line=extracted_finding.sink_line,
                        sanitizers_json=extracted_finding.sanitizers,
                        evidence_json=extracted_finding.evidence,
                        flow_steps_json=[
                            value.model_dump(mode="json") for value in extracted_finding.flow_steps
                        ],
                        remediation_json=extracted_finding.remediation.model_dump(mode="json"),
                        limitations_json=extracted_finding.limitations,
                    )
                )
            await self._codes.replace_findings(project.id, finding_records)
            finding_ids_by_route: dict[UUID, list[str]] = {}
            for finding_record in finding_records:
                if finding_record.static_route_id is not None:
                    finding_ids_by_route.setdefault(finding_record.static_route_id, []).append(
                        str(finding_record.id)
                    )
            for route_record in route_records:
                route_record.findings_json = finding_ids_by_route.get(route_record.id, [])
            project.status = CodeProjectStatus.COMPLETED
            project.analyzed_at = datetime.now(UTC)
            project.warnings_json = sorted(
                {*project.warnings_json, *extraction.warnings, *taint.warnings}
            )[:100]
            project.metadata_json = {
                **project.metadata_json,
                "static_safe_decisions": taint.safe_decisions,
            }
            project.version += 1
            await self._audit.record(
                AuditEventType.CODE_PROJECT_ANALYZED,
                resource_type="code_project",
                resource_id=project.id,
                project_id=project.project_id,
                correlation_id=correlation_id,
                details={
                    "routes": len(route_records),
                    "static_candidates": len(finding_records),
                    "safe_decisions": len(taint.safe_decisions),
                    "code_executed": False,
                },
            )
            await self._session.commit()
            return await self.analysis(code_project_id)
        except Exception:
            await self._session.rollback()
            project = await self._require_project(code_project_id)
            project.status = CodeProjectStatus.FAILED
            await self._session.commit()
            raise

    async def routes(self, code_project_id: UUID) -> list[StaticRoute]:
        project = await self._require_project(code_project_id)
        files = {value.id: value.relative_path for value in project.files}
        return [
            _route_read(value, files.get(value.code_file_id, "unavailable"))
            for value in await self._codes.list_routes(code_project_id)
        ]

    async def analysis(self, code_project_id: UUID) -> CodeAnalysisRead:
        project = await self._require_project(code_project_id)
        routes = await self.routes(code_project_id)
        findings = await self.findings(code_project_id)
        safe_decisions = project.metadata_json.get("static_safe_decisions", [])
        log = [
            "Upload treated as untrusted input; no code or dependency was executed.",
            f"Indexed {project.total_files} supported text files ({project.total_bytes} bytes).",
            "Detected "
            f"{len(project.frameworks_json)} framework signal(s) and {len(routes)} route(s).",
            f"Produced {len(findings)} source-only candidate(s); none are runtime-confirmed.",
        ]
        if isinstance(safe_decisions, list):
            log.extend(str(value) for value in safe_decisions[:20])
        return CodeAnalysisRead(
            project=_project_read(project),
            routes=routes,
            analysis_log=log,
            limitations=[
                "Phase 11 uses intra-procedural Python AST and conservative PHP lexical flows.",
                "Dynamic dispatch, included routers, aliases, middleware, and implicit framework "
                "sanitizers can require manual review.",
                "Static candidates are not Runtime Confirmed and no generated request is sent.",
            ],
        )

    async def findings(self, code_project_id: UUID) -> list[StaticCodeFinding]:
        project = await self._require_project(code_project_id)
        files = {value.id: value.relative_path for value in project.files}
        routes = {value.id: value.path for value in await self._codes.list_routes(code_project_id)}
        return [
            _finding_read(
                value,
                files.get(value.code_file_id, "unavailable"),
                routes.get(value.static_route_id) if value.static_route_id is not None else None,
            )
            for value in await self._codes.list_findings(code_project_id)
        ]

    async def data_flows(self, code_project_id: UUID) -> list[StaticDataFlow]:
        await self._require_project(code_project_id)
        return [_flow_read(value) for value in await self._codes.list_findings(code_project_id)]

    async def _require_project(self, code_project_id: UUID) -> CodeProject:
        project = await self._codes.get(code_project_id)
        if project is None:
            raise EntityNotFoundError("Code project was not found")
        return project

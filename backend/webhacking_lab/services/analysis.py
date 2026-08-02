"""Persisted passive analysis and response-diff application services."""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.analyzers.diff_analyzer import DiffAnalyzer
from webhacking_lab.analyzers.engine import AnalysisEngine
from webhacking_lab.analyzers.models import AnalysisContext, AnalysisFlow, AnalysisResult
from webhacking_lab.api.schemas.resources import (
    AnalysisRunCreate,
    AnalysisRunRead,
    DiffCreate,
    DiffRead,
)
from webhacking_lab.database.models import AnalysisRun
from webhacking_lab.database.repositories.analysis import AnalysisRepository
from webhacking_lab.database.repositories.audit import AuditRepository
from webhacking_lab.database.repositories.http import HttpRepository
from webhacking_lab.database.repositories.projects import WorkspaceRepository
from webhacking_lab.domain.enums import AuditEventType
from webhacking_lab.domain.exceptions import EntityNotFoundError
from webhacking_lab.http_client.models import NormalizedRequest, NormalizedResponse


def _analysis_read(run: AnalysisRun) -> AnalysisRunRead:
    return AnalysisRunRead(
        id=run.id,
        request_id=run.request_id,
        response_id=run.response_id,
        status=run.status,
        results=[AnalysisResult.model_validate(item) for item in run.results_json],
        flow=AnalysisFlow.model_validate(run.flow_json),
        created_at=run.created_at,
    )


class DiffService:
    """Compare only already-redacted persisted responses."""

    def __init__(self, session: AsyncSession) -> None:
        self._http = HttpRepository(session)
        self._analyzer = DiffAnalyzer()

    async def compare(self, data: DiffCreate) -> DiffRead:
        baseline = await self._http.get_response(data.baseline_response_id)
        test = await self._http.get_response(data.test_response_id)
        if baseline is None or test is None:
            raise EntityNotFoundError("One or both HTTP responses were not found")
        result = self._analyzer.compare(
            NormalizedResponse.model_validate(baseline.normalized_json),
            NormalizedResponse.model_validate(test.normalized_json),
            ignore_patterns=data.ignore_patterns,
            jsonpath_ignore=data.jsonpath_ignore,
            css_selector_ignore=data.css_selector_ignore,
        )
        return DiffRead(
            baseline_response_id=baseline.id,
            test_response_id=test.id,
            result=result,
        )


class AnalysisService:
    """Run six passive analyzers without creating any outbound request."""

    def __init__(self, session: AsyncSession, engine: AnalysisEngine | None = None) -> None:
        self._http = HttpRepository(session)
        self._workspaces = WorkspaceRepository(session)
        self._analysis = AnalysisRepository(session)
        self._audit = AuditRepository(session)
        self._engine = engine or AnalysisEngine()

    async def run(
        self,
        data: AnalysisRunCreate,
        correlation_id: str | None,
    ) -> AnalysisRunRead:
        request = await self._http.get_request(data.request_id)
        if request is None:
            raise EntityNotFoundError("HTTP request was not found")
        workspace = await self._workspaces.get(request.workspace_id)
        if workspace is None:
            raise EntityNotFoundError("Workspace was not found")
        response_model = None
        if data.response_id is not None:
            response_model = await self._http.get_response(data.response_id)
            if response_model is None or response_model.request_id != request.id:
                raise EntityNotFoundError("Response was not found for this request")
        elif request.responses:
            response_model = max(request.responses, key=lambda item: item.created_at)
        await self._audit.record(
            AuditEventType.ANALYSIS_STARTED,
            resource_type="http_request",
            resource_id=request.id,
            project_id=workspace.project_id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
            details={"analyzer_count": 6},
        )
        normalized_request = NormalizedRequest.model_validate(request.normalized_json)
        normalized_response = (
            NormalizedResponse.model_validate(response_model.normalized_json)
            if response_model is not None
            else None
        )
        results = await self._engine.analyze(
            normalized_request,
            normalized_response,
            AnalysisContext(
                request_id=request.id,
                response_id=response_model.id if response_model else None,
                network_execution_allowed=False,
            ),
        )
        flow = self._engine.flow(results)
        run = await self._analysis.add(
            AnalysisRun(
                request_id=request.id,
                response_id=response_model.id if response_model else None,
                status="completed",
                results_json=[item.model_dump(mode="json") for item in results],
                flow_json=flow.model_dump(mode="json"),
            )
        )
        await self._audit.record(
            AuditEventType.ANALYSIS_COMPLETED,
            resource_type="analysis_run",
            resource_id=run.id,
            project_id=workspace.project_id,
            workspace_id=workspace.id,
            correlation_id=correlation_id,
            details={
                "result_count": len(results),
                "review_candidates": sum(
                    item.status.value in {"suspicious", "likely"} for item in results
                ),
            },
        )
        return _analysis_read(run)

    async def get(self, analysis_id: UUID) -> AnalysisRunRead:
        run = await self._analysis.get(analysis_id)
        if run is None:
            raise EntityNotFoundError("Analysis run was not found")
        return _analysis_read(run)

    async def get_flow(self, analysis_id: UUID) -> AnalysisFlow:
        return (await self.get(analysis_id)).flow

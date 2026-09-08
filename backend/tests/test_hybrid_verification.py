"""Hybrid correlation of static candidates with runtime scanner evidence."""

from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from webhacking_lab.database.models import (
    CodeFile,
    CodeProject,
    HttpRequest,
    HttpResponse,
    Project,
    ScanFinding,
    ScanJob,
    ScanTestCase,
    StaticFindingRecord,
    StaticRouteRecord,
    Workspace,
)
from webhacking_lab.database.session import Database
from webhacking_lab.domain.enums import (
    ActiveTestStatus,
    ScannerProfile,
    ScanStatus,
    VerificationStatus,
    WorkspaceMode,
)
from webhacking_lab.services.hybrid import (
    RuntimeSignal,
    StaticCandidate,
    correlate,
    derive_verification,
    normalize_path,
    path_matches,
)
from webhacking_lab.services.reports import ReportService

# --- Pure engine -----------------------------------------------------------------


def test_normalize_path_strips_host_and_query() -> None:
    assert normalize_path("http://lab.test/users/7?x=1#f") == ("users", "7")
    assert normalize_path("/Search/") == ("search",)
    assert normalize_path(None) == ()


@pytest.mark.parametrize(
    ("template", "url", "expected"),
    [
        ("/users/<int:id>", "http://lab.test/users/7", True),
        ("/users/{id}", "http://lab.test/users/7", True),
        ("/users/:id", "http://lab.test/users/7", True),
        ("/search", "http://lab.test/search?q=x", True),
        ("/users/<id>", "http://lab.test/users/7/notes", False),
        ("/orders/<id>", "http://lab.test/users/7", False),
        ("", "http://lab.test/users/7", False),
    ],
)
def test_path_matches(template: str, url: str, expected: bool) -> None:
    assert path_matches(template, url) is expected


def _signal(verification: str, *, attempted: bool = False) -> RuntimeSignal:
    return RuntimeSignal(
        origin_id=uuid4(),
        kind="active_test",
        category="sql_injection",
        endpoint_url="http://lab.test/search",
        parameter="q",
        verification=verification,
        confidence=0.9,
        title="SQLi",
        attempted=attempted,
    )


def test_derive_verification_picks_strongest_signal() -> None:
    status, note = derive_verification(
        [_signal(VerificationStatus.SUSPICIOUS.value), _signal(VerificationStatus.CONFIRMED.value)]
    )
    assert status == VerificationStatus.CONFIRMED.value
    assert note is None


def test_derive_verification_attempted_without_signal_is_not_false_positive() -> None:
    status, note = derive_verification(
        [_signal(VerificationStatus.FALSE_POSITIVE.value, attempted=True)]
    )
    assert status == VerificationStatus.NOT_TESTED.value
    assert note is not None and "did not reproduce" in note


def test_derive_verification_no_matches_is_not_tested() -> None:
    assert derive_verification([]) == (VerificationStatus.NOT_TESTED.value, None)


def test_correlate_matches_on_category_path_and_parameter() -> None:
    static = StaticCandidate(
        origin_id=uuid4(),
        category="sql_injection",
        parameter="q",
        path="/search",
        title="SQLi in search",
        severity="high",
        location="app.py:5",
    )
    unrelated = StaticCandidate(
        origin_id=uuid4(),
        category="xss",
        parameter="name",
        path="/profile",
        title="XSS",
        severity="medium",
        location="app.py:9",
    )
    signal = _signal(VerificationStatus.CONFIRMED.value, attempted=True)
    result = correlate([static, unrelated], [signal])

    assert len(result.correlations) == 1
    correlation = result.correlations[0]
    assert correlation.static.origin_id == static.origin_id
    assert correlation.verification == VerificationStatus.CONFIRMED.value
    assert result.static_verification[static.origin_id] == (
        VerificationStatus.CONFIRMED.value,
        1,
    )
    assert result.static_verification[unrelated.origin_id] == (
        VerificationStatus.NOT_TESTED.value,
        0,
    )
    assert result.scanner_root_cause[signal.origin_id] == [static.origin_id]


def test_correlate_rejects_parameter_mismatch() -> None:
    static = StaticCandidate(
        origin_id=uuid4(),
        category="sql_injection",
        parameter="id",
        path="/search",
        title="SQLi",
        severity="high",
        location="app.py:5",
    )
    result = correlate([static], [_signal(VerificationStatus.CONFIRMED.value)])
    assert result.correlations == []


# --- ReportService integration ---------------------------------------------------


async def _seed_project(session: AsyncSession) -> tuple[Project, Workspace]:
    project = Project(name="Target App", mode=WorkspaceMode.CTF)
    workspace = Workspace(project=project, name="ws", mode=WorkspaceMode.CTF)
    session.add_all([project, workspace])
    await session.flush()
    return project, workspace


async def _seed_static_sqli(
    session: AsyncSession, project: Project, path: str
) -> StaticFindingRecord:
    code_project = CodeProject(
        project=project,
        name="src",
        authorization_notes="approved",
        storage_key=str(uuid4()),
    )
    code_file = CodeFile(
        code_project=code_project,
        relative_path="app.py",
        size_bytes=100,
        sha256="0" * 64,
    )
    session.add_all([code_project, code_file])
    await session.flush()
    route = StaticRouteRecord(
        code_project_id=code_project.id,
        code_file_id=code_file.id,
        framework="flask",
        methods_json=["GET"],
        path=path,
        handler_name="search",
        line_start=1,
        line_end=6,
    )
    session.add(route)
    await session.flush()
    record = StaticFindingRecord(
        code_project_id=code_project.id,
        code_file_id=code_file.id,
        static_route_id=route.id,
        category="sql_injection",
        title="Potential SQL Injection",
        status="static_candidate",
        severity="high",
        confidence=0.9,
        parameter="q",
        source_label="request.args['q']",
        sink_label="cursor.execute",
        source_line=3,
        sink_line=5,
    )
    session.add(record)
    await session.flush()
    return record


@pytest.mark.asyncio
async def test_report_promotes_static_candidate_from_active_test() -> None:
    database = Database("sqlite+aiosqlite:///:memory:")
    await database.initialize()
    try:
        async with database.session_factory() as session:
            project, workspace = await _seed_project(session)
            static = await _seed_static_sqli(session, project, "/search")

            scan = ScanJob(
                project_id=project.id,
                workspace_id=workspace.id,
                profile=ScannerProfile.SAFE,
                target="http://lab.test/",
                status=ScanStatus.COMPLETED,
                request_budget=10,
            )
            request = HttpRequest(
                workspace_id=workspace.id,
                method="GET",
                url="http://lab.test/search",
                normalized_json={},
            )
            session.add_all([scan, request])
            await session.flush()
            response = HttpResponse(
                request_id=request.id,
                status_code=200,
                normalized_json={},
            )
            session.add(response)
            await session.flush()
            session.add(
                ScanTestCase(
                    scan_id=scan.id,
                    plugin_id="sql_injection",
                    category="sql_injection",
                    endpoint_url="http://lab.test/search",
                    method="GET",
                    title="SQL injection probe",
                    objective="Confirm SQLi",
                    parameter="q",
                    mutation_type="boolean",
                    preview_value="1 AND 1=1",
                    exact_request_preview="GET /search?q=1 AND 1=1",
                    success_criteria="Differential response",
                    false_positive_notes="",
                    risk_level="safe",
                    status=ActiveTestStatus.COMPLETED,
                    baseline_request_id=request.id,
                    baseline_response_id=response.id,
                    result_status=VerificationStatus.CONFIRMED.value,
                    confidence=0.95,
                    evidence_json=[{"signal": "boolean differential"}],
                )
            )
            await session.commit()
            project_id = project.id

            service = ReportService(session)
            report = await service.build(project_id)
            hybrid = await service.hybrid(project_id)

        static_row = next(f for f in report.findings if f.origin_id == static.id)
        assert static_row.verification == VerificationStatus.CONFIRMED.value
        assert static_row.correlation_count == 1

        assert hybrid.total_static == 1
        assert hybrid.correlated == 1
        assert hybrid.by_verification == {VerificationStatus.CONFIRMED.value: 1}
        correlation = hybrid.correlations[0]
        assert correlation.static_origin_id == static.id
        assert correlation.parameter == "q"
        assert correlation.runtime[0].kind == "active_test"
        assert "boolean differential" in correlation.runtime[0].evidence[0]
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_hybrid_promotes_from_passive_finding_and_leaves_unmatched_untested() -> None:
    database = Database("sqlite+aiosqlite:///:memory:")
    await database.initialize()
    try:
        async with database.session_factory() as session:
            project, workspace = await _seed_project(session)
            static = await _seed_static_sqli(session, project, "/search")

            scan = ScanJob(
                project_id=project.id,
                workspace_id=workspace.id,
                profile=ScannerProfile.PASSIVE,
                target="http://lab.test/",
                status=ScanStatus.COMPLETED,
                request_budget=10,
            )
            session.add(scan)
            await session.flush()
            session.add(
                ScanFinding(
                    scan_id=scan.id,
                    endpoint_url="http://lab.test/search",
                    analyzer="sql_error",
                    category="sql_injection",
                    title="SQL error indicator",
                    summary="Database error reflected.",
                    status=VerificationStatus.SUSPICIOUS.value,
                    severity="high",
                    confidence=0.5,
                    evidence_json=[{"marker": "SQL syntax"}],
                )
            )
            await session.commit()
            project_id = project.id

            service = ReportService(session)
            report = await service.build(project_id)
            hybrid = await service.hybrid(project_id)

        static_row = next(f for f in report.findings if f.origin_id == static.id)
        assert static_row.verification == VerificationStatus.SUSPICIOUS.value
        assert static_row.correlation_count == 1
        assert hybrid.correlated == 1
        assert hybrid.correlations[0].runtime[0].kind == "passive_finding"
    finally:
        await database.close()

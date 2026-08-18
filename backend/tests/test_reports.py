"""Consolidated project report aggregation and export tests."""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from webhacking_lab.database.models import (
    CodeFile,
    CodeProject,
    Project,
    ScanFinding,
    ScanJob,
    StaticFindingRecord,
    Workspace,
)
from webhacking_lab.database.session import Database
from webhacking_lab.domain.enums import (
    ScannerProfile,
    ScanStatus,
    WorkspaceMode,
)
from webhacking_lab.domain.exceptions import EntityNotFoundError
from webhacking_lab.services.reports import ReportService, render_report_markdown


@pytest.mark.asyncio
async def test_report_bundles_static_and_scanner_findings_sorted_by_severity() -> None:
    database = Database("sqlite+aiosqlite:///:memory:")
    await database.initialize()
    try:
        async with database.session_factory() as session:
            project = Project(name="Target App", mode=WorkspaceMode.CTF)
            workspace = Workspace(project=project, name="ws", mode=WorkspaceMode.CTF)
            session.add_all([project, workspace])
            await session.flush()
            scan = ScanJob(
                project_id=project.id,
                workspace_id=workspace.id,
                profile=ScannerProfile.PASSIVE,
                target="http://lab.test/",
                status=ScanStatus.COMPLETED,
                request_budget=10,
            )
            session.add_all(
                [
                    ScanFinding(
                        scan=scan,
                        endpoint_url="http://lab.test/login",
                        analyzer="security_headers",
                        category="security_headers",
                        title="Missing HSTS",
                        summary="No Strict-Transport-Security header.",
                        status="confirmed",
                        severity="critical",
                        confidence=0.9,
                    ),
                    # A not-tested finding must be excluded from the report.
                    ScanFinding(
                        scan=scan,
                        endpoint_url="http://lab.test/x",
                        analyzer="xss",
                        category="xss",
                        title="Untested",
                        summary="Adapter never issued a request.",
                        status="not_tested",
                        severity="high",
                        confidence=0.0,
                    ),
                ]
            )
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
            session.add(
                StaticFindingRecord(
                    code_project_id=code_project.id,
                    code_file_id=code_file.id,
                    category="sql_injection",
                    title="Potential SQL Injection",
                    status="static_candidate",
                    severity="high",
                    confidence=0.9,
                    source_label="request.args['id']",
                    sink_label="cursor.execute",
                    source_line=3,
                    sink_line=5,
                )
            )
            await session.commit()
            project_id = project.id

            service = ReportService(session)
            report = await service.build(project_id)
            scanner_id = report.findings[0].origin_id
            static_id = report.findings[1].origin_id
            scanner_detail = await service.finding_detail(project_id, "scanner", scanner_id)
            static_detail = await service.finding_detail(project_id, "static", static_id)
            with pytest.raises(EntityNotFoundError):
                await service.finding_detail(project_id, "scanner", static_id)
            with pytest.raises(EntityNotFoundError):
                await service.finding_detail(project_id, "unknown", static_id)

        assert scanner_detail.summary == "No Strict-Transport-Security header."
        assert scanner_detail.flow_steps == []
        assert static_detail.location == "app.py:5"
        assert static_detail.summary == "request.args['id'] → cursor.execute"

        assert report.project_name == "Target App"
        assert report.summary.total == 2  # not-tested scanner finding excluded
        assert report.summary.by_source == {"scanner": 1, "static": 1}
        assert report.summary.by_severity == {"critical": 1, "high": 1}
        # Critical scanner finding sorts before the high static finding.
        assert [f.severity for f in report.findings] == ["critical", "high"]
        assert report.findings[0].source == "scanner"
        assert report.findings[0].location == "http://lab.test/login"
        assert report.findings[1].location == "app.py:5"
        assert report.findings[1].detail == "request.args['id'] → cursor.execute"

        markdown = render_report_markdown(report)
        assert "# Security Findings Report: Target App" in markdown
        assert "| critical | scanner | security_headers | Missing HSTS |" in markdown
        assert "Untested" not in markdown
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_report_for_unknown_project_raises() -> None:
    database = Database("sqlite+aiosqlite:///:memory:")
    await database.initialize()
    try:
        async with database.session_factory() as session:
            with pytest.raises(EntityNotFoundError):
                await ReportService(session).build(uuid4())
    finally:
        await database.close()


def _project(client: TestClient) -> str:
    response = client.post(
        "/api/projects",
        json={"name": "Report Project", "description": "", "mode": "ctf"},
    )
    assert response.status_code == 201
    return str(response.json()["id"])


def test_project_report_endpoints_expose_static_findings(client: TestClient) -> None:
    project_id = _project(client)
    created = client.post(
        "/api/code-projects",
        json={
            "project_id": project_id,
            "name": "src",
            "description": "",
            "authorization_confirmed": True,
            "authorization_notes": "Organizer approved this exact source review.",
            "confirmation_phrase": "UPLOAD INERT SOURCE",
        },
    )
    assert created.status_code == 201
    code_project_id = created.json()["id"]
    source = (
        b'from flask import request\n\n'
        b'@app.route("/item")\n'
        b"def handler():\n"
        b'    item = request.args["id"]\n'
        b'    return cursor.execute("SELECT " + item)\n'
    )
    upload = client.post(
        "/api/code-projects/upload",
        data={"code_project_id": code_project_id},
        files=[("files", ("app.py", source, "text/x-python"))],
    )
    assert upload.status_code == 201, upload.text
    assert client.post(f"/api/code-projects/{code_project_id}/analyze").status_code == 200

    report = client.get(f"/api/projects/{project_id}/report")
    assert report.status_code == 200
    payload = report.json()
    assert payload["summary"]["total"] >= 1
    assert payload["summary"]["by_source"].get("static", 0) >= 1
    assert any(f["source"] == "static" for f in payload["findings"])

    markdown = client.get(f"/api/projects/{project_id}/report/markdown")
    assert markdown.status_code == 200
    assert markdown.headers["content-type"].startswith("text/markdown")
    assert "Security Findings Report" in markdown.text

    static_finding = next(f for f in payload["findings"] if f["source"] == "static")
    detail = client.get(
        f"/api/projects/{project_id}/report/findings/static/{static_finding['origin_id']}"
    )
    assert detail.status_code == 200
    detail_payload = detail.json()
    assert detail_payload["source"] == "static"
    assert len(detail_payload["flow_steps"]) >= 1
    assert detail_payload["remediation"]
    missing = client.get(
        f"/api/projects/{project_id}/report/findings/static/{uuid4()}"
    )
    assert missing.status_code == 404


def test_project_report_is_empty_for_project_without_findings(client: TestClient) -> None:
    project_id = _project(client)
    report = client.get(f"/api/projects/{project_id}/report")
    assert report.status_code == 200
    assert report.json()["summary"]["total"] == 0
    assert client.get("/api/projects/" + str(uuid4()) + "/report").status_code == 404

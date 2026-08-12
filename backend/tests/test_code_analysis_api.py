"""API integration tests for inert source upload and route inventory."""

import io
import stat
import zipfile
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import update

from webhacking_lab.database.models import CodeProject


def _parent_project(client: TestClient) -> str:
    response = client.post(
        "/api/projects",
        json={
            "name": "Source Review",
            "description": "Authorized local source review",
            "mode": "ctf",
        },
    )
    assert response.status_code == 201
    return str(response.json()["id"])


def _code_project(client: TestClient, parent_id: str) -> dict[str, object]:
    response = client.post(
        "/api/code-projects",
        json={
            "project_id": parent_id,
            "name": "Uploaded challenge",
            "description": "Static inspection only",
            "authorization_confirmed": True,
            "authorization_notes": "Organizer approved this exact source review.",
            "confirmation_phrase": "UPLOAD INERT SOURCE",
        },
    )
    assert response.status_code == 201
    return response.json()


def _zip(entries: dict[str, bytes], *, symlink: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "target.py")
    return buffer.getvalue()


def test_upload_analyze_and_read_redacted_source(client: TestClient, tmp_path: Path) -> None:
    parent_id = _parent_project(client)
    project = _code_project(client, parent_id)
    marker = tmp_path / "must-not-exist"
    source = """from flask import Flask, request
from pathlib import Path

app = Flask(__name__)
API_KEY = "super-secret-value"
Path(__MARKER__).write_text("executed")

@app.route("/product/<int:item_id>", methods=["GET"])
@login_required
def product(item_id):
    search = request.args.get("q")
    query = f"SELECT * FROM products WHERE name = '{search}'"
    return cursor.execute(query)
""".replace("__MARKER__", repr(str(marker)))
    upload = client.post(
        "/api/code-projects/upload",
        data={"code_project_id": project["id"]},
        files=[
            ("files", ("app.py", source, "text/x-python")),
            ("files", ("requirements.txt", "Flask==3.1.0\n", "text/plain")),
        ],
    )
    assert upload.status_code == 201, upload.text
    payload = upload.json()
    assert payload["execution_performed"] is False
    assert payload["project"]["frameworks"] == ["Flask"]
    assert payload["project"]["secret_findings_count"] == 1
    assert not marker.exists()

    analysis = client.post(f"/api/code-projects/{project['id']}/analyze")
    assert analysis.status_code == 200, analysis.text
    route = analysis.json()["routes"][0]
    assert route["methods"] == ["GET"]
    assert route["path"] == "/product/<int:item_id>"
    assert route["handler_name"] == "product"
    assert route["authentication"]["required"] is True
    assert {value["name"] for value in route["parameters"]} == {"item_id", "q"}
    assert len(route["findings"]) == 1

    findings = client.get(f"/api/code-projects/{project['id']}/findings")
    assert findings.status_code == 200
    finding = findings.json()[0]
    assert finding["category"] == "sql_injection"
    assert finding["status"] == "static_candidate"
    assert finding["route"] == "/product/<int:item_id>"
    assert finding["parameter"] == "q"
    assert finding["sink_label"] == "cursor.execute"
    flows = client.get(f"/api/code-projects/{project['id']}/data-flows")
    assert flows.status_code == 200
    assert flows.json()[0]["finding_id"] == finding["id"]
    assert flows.json()[0]["nodes"][0]["kind"] == "source"
    assert flows.json()[0]["nodes"][-1]["kind"] == "sink"

    file_id = next(value["id"] for value in payload["files"] if value["relative_path"] == "app.py")
    content = client.get(f"/api/code-projects/{project['id']}/files/{file_id}")
    assert content.status_code == 200
    assert "super-secret-value" not in content.json()["content"]
    assert "<redacted-secret>" in content.json()["content"]
    assert content.json()["redacted"] is True

    listing = client.get(f"/api/code-projects?project_id={parent_id}")
    assert listing.status_code == 200
    assert listing.json()[0]["status"] == "completed"
    assert (
        client.get(f"/api/code-projects/{project['id']}/routes").json()[0]["file_path"] == "app.py"
    )
    assert client.get(f"/api/code-projects/{project['id']}/analysis").status_code == 200


def test_zip_upload_detects_php_and_file_endpoint(client: TestClient) -> None:
    project = _code_project(client, _parent_project(client))
    upload = client.post(
        "/api/code-projects/upload",
        data={"code_project_id": project["id"]},
        files={
            "files": (
                "challenge.zip",
                _zip(
                    {
                        "public/index.php": (
                            b'<?php $id = $_GET["id"]; '
                            b'$query = "SELECT * FROM users WHERE id = " . $id; '
                            b"mysqli_query($conn, $query);"
                        ),
                        "composer.json": b'{"require":{"php":"^8.3"}}',
                    }
                ),
                "application/zip",
            )
        },
    )
    assert upload.status_code == 201, upload.text
    assert upload.json()["project"]["frameworks"] == ["Plain PHP"]
    analysis = client.post(f"/api/code-projects/{project['id']}/analyze")
    assert analysis.status_code == 200
    assert analysis.json()["routes"][0]["path"] == "/public/"
    assert analysis.json()["routes"][0]["methods"] == ["GET", "POST"]
    findings = client.get(f"/api/code-projects/{project['id']}/findings").json()
    assert findings[0]["category"] == "sql_injection"
    assert findings[0]["file_path"] == "public/index.php"


def test_upload_rejects_zip_slip_and_symbolic_link(client: TestClient) -> None:
    for name, archive in (
        ("slip", _zip({"../outside.py": b"print('no')"})),
        ("link", _zip({"safe.py": b"pass"}, symlink="linked.py")),
    ):
        project = _code_project(client, _parent_project(client))
        response = client.post(
            "/api/code-projects/upload",
            data={"code_project_id": project["id"]},
            files={"files": (f"{name}.zip", archive, "application/zip")},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "invalid_source_upload"
        assert client.get(f"/api/code-projects/{project['id']}/files").json() == []


def test_upload_rejects_archive_bomb_executable_and_duplicate_upload(
    client: TestClient,
) -> None:
    bomb_project = _code_project(client, _parent_project(client))
    bomb = client.post(
        "/api/code-projects/upload",
        data={"code_project_id": bomb_project["id"]},
        files={
            "files": (
                "bomb.zip",
                _zip({"huge.py": b"A" * 200_001}),
                "application/zip",
            )
        },
    )
    assert bomb.status_code == 413

    executable_project = _code_project(client, _parent_project(client))
    executable = client.post(
        "/api/code-projects/upload",
        data={"code_project_id": executable_project["id"]},
        files={"files": ("payload.exe", b"MZpayload", "application/octet-stream")},
    )
    assert executable.status_code == 422

    source_project = _code_project(client, _parent_project(client))
    accepted = client.post(
        "/api/code-projects/upload",
        data={"code_project_id": source_project["id"]},
        files={"files": ("main.py", b"print('safe')", "text/x-python")},
    )
    assert accepted.status_code == 201
    duplicate = client.post(
        "/api/code-projects/upload",
        data={"code_project_id": source_project["id"]},
        files={"files": ("other.py", b"pass", "text/x-python")},
    )
    assert duplicate.status_code == 409


def test_code_project_state_and_identity_errors(client: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000001"
    unauthorized = client.post(
        "/api/code-projects",
        json={
            "project_id": missing,
            "name": "unauthorized",
            "description": "Static inspection only",
            "authorization_confirmed": False,
            "authorization_notes": "No permission has been confirmed.",
            "confirmation_phrase": "UPLOAD INERT SOURCE",
        },
    )
    assert unauthorized.status_code == 422
    create = client.post(
        "/api/code-projects",
        json={
            "project_id": missing,
            "name": "missing",
            "description": "",
            "authorization_confirmed": True,
            "authorization_notes": "Authorized source review for missing parent.",
            "confirmation_phrase": "UPLOAD INERT SOURCE",
        },
    )
    assert create.status_code == 404
    project = _code_project(client, _parent_project(client))
    assert client.post(f"/api/code-projects/{project['id']}/analyze").status_code == 409
    unsupported = client.post(
        "/api/code-projects/upload",
        data={"code_project_id": project["id"]},
        files={"files": ("image.png", b"plain-but-unsupported", "text/plain")},
    )
    assert unsupported.status_code == 422
    mime_mismatch = client.post(
        "/api/code-projects/upload",
        data={"code_project_id": project["id"]},
        files={"files": ("source.py", b"pass", "image/png")},
    )
    assert mime_mismatch.status_code == 422
    assert client.get(f"/api/code-projects/{missing}").status_code == 404
    assert client.get(f"/api/code-projects/{project['id']}/files/{missing}").status_code == 404


def test_legacy_unconfirmed_code_project_blocks_upload_and_audits(client: TestClient) -> None:
    project = _code_project(client, _parent_project(client))

    async def revoke_authorization() -> None:
        async with client.app.state.database.session_factory() as session:
            await session.execute(
                update(CodeProject)
                .where(CodeProject.id == UUID(str(project["id"])))
                .values(authorization_confirmed=False, authorization_notes="")
            )
            await session.commit()

    assert client.portal is not None
    client.portal.call(revoke_authorization)
    blocked = client.post(
        "/api/code-projects/upload",
        data={"code_project_id": project["id"]},
        files={"files": ("app.py", b"print('inert')", "text/x-python")},
    )
    assert blocked.status_code == 403
    assert blocked.json()["code"] == "authorization_required"
    assert client.get(f"/api/code-projects/{project['id']}/files").json() == []
    audits = client.get("/api/audit-events?limit=20").json()
    assert any(event["event_type"] == "code_project.upload_blocked" for event in audits)

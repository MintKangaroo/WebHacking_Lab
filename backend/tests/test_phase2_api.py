"""Project, workspace, scope, HTTP data, and audit API contracts."""

import json
from typing import Any

from fastapi.testclient import TestClient


def _create_project(client: TestClient) -> dict[str, Any]:
    response = client.post(
        "/api/projects",
        json={
            "name": "Local Shop Review",
            "description": "Authorized local training project",
            "mode": "local_lab",
        },
        headers={"X-Correlation-ID": "project-create"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_project_workspace_scope_crud_and_optimistic_locking(client: TestClient) -> None:
    project = _create_project(client)
    project_id = project["id"]
    workspace = project["workspaces"][0]

    assert project["workspace_count"] == 1
    assert project["scope_rule_count"] == 6
    assert workspace["network_execution_enabled"] is False
    assert client.get("/api/projects").json()[0]["id"] == project_id

    patch = client.patch(
        f"/api/projects/{project_id}",
        json={"name": "Updated Lab", "version": project["version"]},
    )
    assert patch.status_code == 200
    assert patch.json()["version"] == 2
    stale = client.patch(
        f"/api/projects/{project_id}",
        json={"description": "stale", "version": project["version"]},
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "conflict"

    updated_workspace = client.patch(
        f"/api/workspaces/{workspace['id']}",
        json={"analysis_mode": "hybrid", "request_budget": 25, "version": 1},
    )
    assert updated_workspace.status_code == 200
    assert updated_workspace.json()["analysis_mode"] == "hybrid"
    assert updated_workspace.json()["network_execution_enabled"] is False

    added_workspace = client.post(
        "/api/workspaces",
        json={
            "project_id": project_id,
            "name": "CTF Notes",
            "analysis_mode": "manual_http",
            "request_budget": 10,
        },
    )
    assert added_workspace.status_code == 201
    assert client.get(f"/api/workspaces/{added_workspace.json()['id']}").status_code == 200

    delete = client.delete(f"/api/projects/{project_id}")
    assert delete.status_code == 204
    assert client.get(f"/api/projects/{project_id}").status_code == 404


def test_external_scope_requires_authorization_and_scope_check_is_audited(
    client: TestClient,
) -> None:
    project = _create_project(client)
    project_id = project["id"]
    denied_registration = client.post(
        f"/api/projects/{project_id}/scope",
        json={"scheme": "https", "hostname": "ctf.example", "authorization_confirmed": False},
    )
    assert denied_registration.status_code == 422
    assert denied_registration.json()["code"] == "invalid_scope"

    registered = client.post(
        f"/api/projects/{project_id}/scope",
        json={
            "scheme": "https",
            "hostname": "ctf.example",
            "path_prefix": "/challenge",
            "authorization_confirmed": True,
            "authorization_notes": "Competition scope authorized by organizer",
        },
    )
    assert registered.status_code == 201
    assert len(client.get(f"/api/projects/{project_id}/scope").json()) == 7

    allowed = client.post(
        f"/api/projects/{project_id}/scope/check",
        json={"url": "http://127.0.0.1/local"},
    )
    blocked = client.post(
        f"/api/projects/{project_id}/scope/check",
        json={"url": "http://169.254.169.254/latest/meta-data"},
    )
    assert allowed.json()["allowed"] is True
    assert blocked.json()["code"] == "metadata_blocked"

    audits = client.get("/api/audit-events?limit=20").json()
    assert any(event["event_type"] == "scope.checked" for event in audits)
    assert any(event["correlation_id"] == "project-create" for event in audits)


def test_curl_preview_persist_clone_and_get_are_redacted(client: TestClient) -> None:
    project = _create_project(client)
    workspace_id = project["workspaces"][0]["id"]
    command = (
        "curl -H 'Authorization: Bearer not-stored' "
        "-b 'session=not-stored' 'http://127.0.0.1:5000/search?q=demo'"
    )

    preview = client.post("/api/requests/import/curl", json={"command": command})
    assert preview.status_code == 200
    assert preview.json()["request_ids"] == []
    assert "not-stored" not in preview.text

    persisted = client.post(
        "/api/requests/import/curl",
        json={"command": command, "workspace_id": workspace_id, "persist": True},
    )
    assert persisted.status_code == 200
    request_id = persisted.json()["request_ids"][0]
    stored = client.get(f"/api/requests/{request_id}")
    assert stored.status_code == 200
    assert stored.json()["source"] == "curl"
    assert len(stored.json()["revisions"]) == 1
    assert "not-stored" not in stored.text

    clone = client.post(f"/api/requests/{request_id}/clone")
    assert clone.status_code == 201
    assert clone.json()["id"] != request_id
    assert clone.json()["source"] == "clone"


def test_manual_request_and_har_response_persistence(client: TestClient) -> None:
    project = _create_project(client)
    workspace_id = project["workspaces"][0]["id"]
    manual = client.post(
        "/api/requests",
        json={
            "workspace_id": workspace_id,
            "method": "POST",
            "url": "http://localhost/login",
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "body": '{"username":"learner","password":"hidden"}',
        },
    )
    assert manual.status_code == 201
    assert "hidden" not in manual.text

    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://localhost/profile",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"text": '{"access_token":"hidden"}'},
                    },
                }
            ]
        }
    }
    imported = client.post(
        "/api/requests/import/har",
        json={"content": json.dumps(har), "workspace_id": workspace_id, "persist": True},
    )
    assert imported.status_code == 200
    request_id = imported.json()["request_ids"][0]
    request = client.get(f"/api/requests/{request_id}").json()
    response_id = request["responses"][0]["id"]
    response = client.get(f"/api/responses/{response_id}")
    assert response.status_code == 200
    assert "hidden" not in response.text


def test_api_rejects_missing_workspace_malformed_imports_and_unknown_resources(
    client: TestClient,
) -> None:
    missing_workspace = client.post(
        "/api/requests/import/curl",
        json={"command": "curl http://localhost/", "persist": True},
    )
    malformed_har = client.post(
        "/api/requests/import/har",
        json={"content": "not-json"},
    )
    missing = client.get("/api/projects/00000000-0000-0000-0000-000000000000")
    assert missing_workspace.status_code == 422
    assert malformed_har.status_code == 422
    assert missing.status_code == 404


def test_openapi_includes_phase2_contracts(client: TestClient) -> None:
    paths = client.get("/api/openapi.json").json()["paths"]
    assert "/api/projects" in paths
    assert "/api/projects/{project_id}/scope/check" in paths
    assert "/api/requests/import/curl" in paths
    assert "/api/requests/{request_id}/clone" in paths
    assert "/api/audit-events" in paths

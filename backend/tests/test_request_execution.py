"""Controlled external request policy and API regression tests."""

from collections.abc import Iterator, Sequence
from typing import Any

import pytest
from fastapi.testclient import TestClient

from webhacking_lab.api.app import create_app
from webhacking_lab.core.config import Settings
from webhacking_lab.core.rate_limit import RequestGate
from webhacking_lab.domain.exceptions import RateLimitError
from webhacking_lab.http_client.client import SingleHopSender, TransportResult


class FakeResolver:
    """Return a stable public address without using test network access."""

    async def resolve(self, hostname: str, port: int) -> Sequence[str]:
        del hostname, port
        return ["93.184.216.34"]


class FakeSender(SingleHopSender):
    """Capture approved calls and provide a bounded redirect chain."""

    def __init__(self, responses: list[TransportResult]) -> None:
        self.responses = responses
        self.calls: list[dict[str, object]] = []

    async def send(
        self,
        *,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        resolved_ips: list[str],
        expected_hostname: str,
    ) -> TransportResult:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "resolved_ips": resolved_ips,
                "expected_hostname": expected_hostname,
            }
        )
        return self.responses.pop(0)


@pytest.fixture
def execution_client() -> Iterator[tuple[TestClient, FakeSender]]:
    """Run the API with both global execution switches explicitly enabled."""

    settings = Settings(
        environment="test",
        database_url="sqlite+aiosqlite:///:memory:",
        analysis_only=False,
        network_execution_enabled=True,
    )
    sender = FakeSender(
        [
            TransportResult(
                status_code=302,
                reason="Found",
                headers=[("Location", "/allowed/final")],
                body=b"",
                elapsed_ms=2.0,
            ),
            TransportResult(
                status_code=200,
                reason="OK",
                headers=[
                    ("Content-Type", "application/json"),
                    ("Set-Cookie", "session=upstream-secret; HttpOnly"),
                ],
                body=b'{"access_token":"upstream-secret","message":"ok"}',
                elapsed_ms=3.0,
            ),
        ]
    )
    with TestClient(create_app(settings)) as client:
        client.app.state.dns_resolver = FakeResolver()
        client.app.state.http_sender = sender
        yield client, sender


def _prepare_external_request(client: TestClient, *, method: str = "GET") -> dict[str, Any]:
    project = client.post(
        "/api/projects",
        json={"name": "Authorized Target", "mode": "authorized_pentest"},
    ).json()
    project_id = project["id"]
    workspace = project["workspaces"][0]
    scope = client.post(
        f"/api/projects/{project_id}/scope",
        json={
            "scheme": "https",
            "hostname": "authorized.example",
            "path_prefix": "/allowed",
            "authorization_confirmed": True,
            "authorization_notes": "Written authorization for this exact assessment scope",
            "max_requests_per_minute": 10,
            "max_concurrency": 1,
        },
    )
    assert scope.status_code == 201, scope.text
    enabled = client.post(
        f"/api/workspaces/{workspace['id']}/execution/enable",
        json={
            "authorization_confirmed": True,
            "confirmation_phrase": "ENABLE CONTROLLED REQUESTS",
            "expected_use": "Read-only validation for the authorized assessment",
            "version": workspace["version"],
        },
    )
    assert enabled.status_code == 200, enabled.text
    request = client.post(
        "/api/requests",
        json={
            "workspace_id": workspace["id"],
            "method": method,
            "url": "https://authorized.example/allowed/start?view=summary&token=not-stored",
            "headers": [
                {"name": "Accept", "value": "application/json"},
                {"name": "Authorization", "value": "Bearer not-stored"},
                {"name": "Cookie", "value": "session=not-stored"},
            ],
        },
    )
    assert request.status_code == 201, request.text
    return request.json()


def test_external_request_requires_preview_and_follows_only_rescoped_redirects(
    execution_client: tuple[TestClient, FakeSender],
) -> None:
    client, sender = execution_client
    request = _prepare_external_request(client)

    preview_response = client.post(f"/api/requests/{request['id']}/execute/preview")
    assert preview_response.status_code == 200, preview_response.text
    preview = preview_response.json()
    assert preview["scope"]["allowed"] is True
    assert preview["scope"]["resolved_ips"] == ["93.184.216.34"]
    assert preview["maximum_request_count"] == 5
    assert "not-stored" not in preview_response.text
    assert "Authorization" not in preview["exact_request"]
    assert "token=" not in preview["target_url"]

    executed = client.post(
        f"/api/requests/{request['id']}/execute",
        json={
            "confirmation_phrase": "SEND UP TO 5 SAFE REQUESTS",
            "approval_token": preview["approval_token"],
            "request_version": request["version"],
        },
        headers={"X-Correlation-ID": "external-execution"},
    )
    assert executed.status_code == 201, executed.text
    result = executed.json()
    assert result["response"]["status_code"] == 200
    assert result["requests_used"] == 2
    assert len(result["response"]["normalized"]["redirect_history"]) == 1
    assert "upstream-secret" not in executed.text
    assert len(sender.calls) == 2
    assert all(call["resolved_ips"] == ["93.184.216.34"] for call in sender.calls)
    assert all(call["expected_hostname"] == "authorized.example" for call in sender.calls)

    audits = client.get("/api/audit-events?limit=30").json()
    assert any(event["event_type"] == "request.execution_completed" for event in audits)
    assert any(event["correlation_id"] == "external-execution" for event in audits)


def test_state_changing_method_is_blocked_and_audited(
    execution_client: tuple[TestClient, FakeSender],
) -> None:
    client, sender = execution_client
    request = _prepare_external_request(client, method="POST")
    preview = client.post(f"/api/requests/{request['id']}/execute/preview")
    assert preview.status_code == 403
    assert preview.json()["code"] == "execution_blocked"
    assert sender.calls == []
    audits = client.get("/api/audit-events?limit=20").json()
    assert any(event["event_type"] == "request.execution_blocked" for event in audits)


def test_server_default_prevents_workspace_execution_enable(client: TestClient) -> None:
    project = client.post(
        "/api/projects",
        json={"name": "Analysis only", "mode": "local_lab"},
    ).json()
    workspace = project["workspaces"][0]
    response = client.post(
        f"/api/workspaces/{workspace['id']}/execution/enable",
        json={
            "authorization_confirmed": True,
            "confirmation_phrase": "ENABLE CONTROLLED REQUESTS",
            "expected_use": "Approved local test request only",
            "version": workspace["version"],
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == "execution_blocked"


@pytest.mark.asyncio
async def test_request_gate_enforces_rate_and_releases_concurrency() -> None:
    now = 100.0
    gate = RequestGate(clock=lambda: now)
    async with gate.slot(
        "https://authorized.example",
        global_per_minute=2,
        target_per_minute=1,
        max_concurrency=1,
    ):
        with pytest.raises(RateLimitError):
            await gate.acquire(
                "https://authorized.example",
                global_per_minute=2,
                target_per_minute=1,
                max_concurrency=1,
            )
    with pytest.raises(RateLimitError):
        await gate.acquire(
            "https://authorized.example",
            global_per_minute=2,
            target_per_minute=1,
            max_concurrency=1,
        )

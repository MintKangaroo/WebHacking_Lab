"""Scanner API, shared execution gateway, budget, and cancellation tests."""

import time
from collections.abc import Coroutine, Iterator, Sequence
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from fastapi.testclient import TestClient

from webhacking_lab.api.app import create_app
from webhacking_lab.core.config import Settings
from webhacking_lab.http_client.client import SingleHopSender, TransportResult


class PublicResolver:
    """Resolve test hosts without any external DNS access."""

    async def resolve(self, hostname: str, port: int) -> Sequence[str]:
        del hostname, port
        return ["93.184.216.34"]


class ScannerSender(SingleHopSender):
    """Return one static HTML document and capture the exact outbound URL."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.methods: list[str] = []

    async def send(
        self,
        *,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        resolved_ips: list[str],
        expected_hostname: str,
        max_response_bytes: int | None = None,
    ) -> TransportResult:
        del resolved_ips, expected_hostname, max_response_bytes
        self.calls.append(url)
        self.methods.append(method)
        query = parse_qs(urlsplit(url).query)
        if method == "OPTIONS":
            origin = next((value for name, value in headers if name.lower() == "origin"), "")
            return TransportResult(
                status_code=204,
                reason="No Content",
                headers=[
                    ("Access-Control-Allow-Origin", origin),
                    ("Access-Control-Allow-Credentials", "true"),
                ],
                body=b"",
                elapsed_ms=1,
            )
        if any(value.endswith("'") for values in query.values() for value in values):
            return TransportResult(
                status_code=500,
                reason="Internal Server Error",
                headers=[("Content-Type", "text/html")],
                body=b"sqlite3.OperationalError: near quote: syntax error",
                elapsed_ms=2,
            )
        redirect = next(
            (
                value
                for name in ("next", "url", "redirect", "return_to")
                for value in query.get(name, [])
                if value.startswith("https://example.invalid/")
            ),
            None,
        )
        if redirect:
            return TransportResult(
                status_code=302,
                reason="Found",
                headers=[("Content-Type", "text/plain"), ("Location", redirect)],
                body=b"redirect",
                elapsed_ms=1,
            )
        if url.endswith("/robots.txt"):
            return TransportResult(
                status_code=200,
                reason="OK",
                headers=[("Content-Type", "text/plain")],
                body=b"Disallow: /admin\nAllow: /public\nSitemap: /sitemap.xml",
                elapsed_ms=1,
            )
        if url.endswith("/sitemap.xml"):
            return TransportResult(
                status_code=200,
                reason="OK",
                headers=[("Content-Type", "application/xml")],
                body=(
                    b"<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
                    b"<url><loc>https://authorized.example/catalog?id=9</loc></url></urlset>"
                ),
                elapsed_ms=1,
            )
        if url.endswith("/openapi.json"):
            return TransportResult(
                status_code=200,
                reason="OK",
                headers=[("Content-Type", "application/json")],
                body=(
                    b'{"openapi":"3.1.0","paths":{"/api/products":'
                    b'{"get":{"parameters":[{"name":"page","in":"query"}]},'
                    b'"post":{"requestBody":{"content":{"application/json":'
                    b'{"schema":{"properties":{"name":{}}}}}}}}}}'
                ),
                elapsed_ms=1,
            )
        if url.endswith("/swagger.json"):
            return TransportResult(
                status_code=404,
                reason="Not Found",
                headers=[("Content-Type", "text/plain")],
                body=b"not found",
                elapsed_ms=1,
            )
        return TransportResult(
            status_code=200,
            reason="OK",
            headers=[
                ("Content-Type", "text/html; charset=utf-8"),
                ("Server", "scanner-test"),
                ("Access-Control-Allow-Origin", "*"),
            ],
            body=(
                b"<html><head><title>Scanner demo</title></head><body>"
                b"<a href='/next?id=7&token=secret'>Next</a>"
                b"<form action='/search' method='get'><input name='q'></form>"
                b"<script>fetch('/api/items?page=2')</script>"
                + f"<p>{url}</p>".encode()
                + b"</body></html>"
            ),
            elapsed_ms=2,
        )


def _prepare_target(client: TestClient) -> tuple[str, str]:
    project = client.post(
        "/api/projects",
        json={"name": "Scanner target", "mode": "authorized_pentest"},
    ).json()
    workspace = project["workspaces"][0]
    scope = client.post(
        f"/api/projects/{project['id']}/scope",
        json={
            "scheme": "https",
            "hostname": "authorized.example",
            "path_prefix": "/",
            "authorization_confirmed": True,
            "authorization_notes": "Written authorization for passive discovery",
            "max_requests_per_minute": 120,
            "max_concurrency": 1,
        },
    )
    assert scope.status_code == 201, scope.text
    enabled = client.post(
        f"/api/workspaces/{workspace['id']}/execution/enable",
        json={
            "authorization_confirmed": True,
            "confirmation_phrase": "ENABLE CONTROLLED REQUESTS",
            "expected_use": "Bounded passive URL inventory collection",
            "version": workspace["version"],
        },
    )
    assert enabled.status_code == 200, enabled.text
    return project["id"], workspace["id"]


def _scan_payload(project_id: str, workspace_id: str, target: str) -> dict[str, object]:
    return {
        "project_id": project_id,
        "workspace_id": workspace_id,
        "target": target,
        "profile": "passive",
        "crawl_policy": {
            "max_depth": 1,
            "max_pages": 1,
            "max_requests": 1,
            "requests_per_second": 5,
            "concurrency": 1,
        },
        "authorization_confirmed": True,
        "confirmation_phrase": "START PASSIVE SCAN",
        "expected_use": "Authorized passive endpoint and parameter inventory",
    }


def _wait_for_terminal(client: TestClient, scan_id: str) -> dict[str, object]:
    for _ in range(600):
        response = client.get(f"/api/scans/{scan_id}")
        assert response.status_code == 200, response.text
        job = response.json()
        if job["status"] in {"completed", "cancelled", "failed", "blocked"}:
            return job
        time.sleep(0.01)
    raise AssertionError("scanner job did not reach a terminal state")


@contextmanager
def scanner_client(*, ctf_mode: bool = False) -> Iterator[tuple[TestClient, ScannerSender]]:
    with TemporaryDirectory(prefix="webhacking-scanner-test-") as directory:
        settings = Settings(
            environment="test",
            database_url=f"sqlite+aiosqlite:///{directory}/scanner.db",
            analysis_only=False,
            network_execution_enabled=True,
            ctf_mode_enabled=ctf_mode,
            global_requests_per_minute=120,
        )
        sender = ScannerSender()
        with TestClient(create_app(settings)) as client:
            client.app.state.dns_resolver = PublicResolver()
            client.app.state.http_sender = sender
            yield client, sender


def test_passive_scan_builds_inventory_findings_and_audit_without_secret_replay() -> None:
    with scanner_client() as (client, sender):
        project_id, workspace_id = _prepare_target(client)
        created = client.post(
            "/api/scans",
            json=_scan_payload(
                project_id,
                workspace_id,
                "https://authorized.example/?token=seed-secret",
            ),
            headers={"X-Correlation-ID": "passive-scan-test"},
        )
        assert created.status_code == 202, created.text
        scan_id = created.json()["id"]
        assert "seed-secret" not in created.text
        job = _wait_for_terminal(client, scan_id)
        assert job["status"] == "completed"
        assert job["requests_used"] == 1
        assert job["request_budget"] == 1
        assert job["endpoints_count"] >= 4
        assert job["parameters_count"] >= 4
        assert job["findings_count"] >= 1
        assert sender.calls == ["https://authorized.example/"]

        endpoints = client.get(f"/api/scans/{scan_id}/endpoints").json()
        assert any(item["url"].endswith("/next?id=7&token=%5BREDACTED%5D") for item in endpoints)
        assert any(item["source"] == "javascript_static" for item in endpoints)
        parameters = client.get(f"/api/scans/{scan_id}/parameters").json()
        token = next(item for item in parameters if item["name"] == "token")
        assert token["sample_value"] == "[REDACTED]"
        assert {item["name"] for item in parameters} >= {"id", "token", "q", "page"}
        findings = client.get(f"/api/scans/{scan_id}/findings").json()
        assert any(item["analyzer"] == "security-header-analyzer" for item in findings)
        events = client.get(f"/api/scans/{scan_id}/events").json()
        assert events[-1]["stage"] == "Completed"
        audits = client.get("/api/audit-events?limit=100").json()
        assert any(item["event_type"] == "scan.completed" for item in audits)
        assert any(item["correlation_id"] == "passive-scan-test" for item in audits)


def test_scanner_rejects_out_of_scope_and_unsupported_profiles() -> None:
    with scanner_client() as (client, sender):
        project_id, workspace_id = _prepare_target(client)
        blocked = client.post(
            "/api/scans",
            json=_scan_payload(project_id, workspace_id, "https://outside.example/"),
        )
        assert blocked.status_code == 403
        assert blocked.json()["code"] == "execution_blocked"
        active_payload = _scan_payload(
            project_id,
            workspace_id,
            "https://authorized.example/",
        )
        active_payload["profile"] = "local_lab"
        active = client.post("/api/scans", json=active_payload)
        assert active.status_code == 403
        assert sender.calls == []


def test_safe_scan_stops_for_exact_approval_then_records_runtime_evidence() -> None:
    with scanner_client() as (client, sender):
        project_id, workspace_id = _prepare_target(client)
        payload = _scan_payload(
            project_id,
            workspace_id,
            "https://authorized.example/?id=1&next=%2Fhome",
        )
        payload.update(
            {
                "profile": "safe",
                "confirmation_phrase": "START SAFE SCAN",
                "active_test_policy": {
                    "enabled": True,
                    "max_tests": 6,
                    "max_tests_per_parameter": 6,
                    "allow_limited_timing": False,
                },
            }
        )
        created = client.post(
            "/api/scans",
            json=payload,
            headers={"X-Correlation-ID": "safe-scan-test"},
        )
        assert created.status_code == 202, created.text
        scan_id = created.json()["id"]
        for _ in range(600):
            job = client.get(f"/api/scans/{scan_id}").json()
            if job["status"] == "waiting_for_approval":
                break
            time.sleep(0.01)
        else:
            raise AssertionError("SAFE scan did not stop for approval")
        assert sender.calls == ["https://authorized.example/?id=1&next=%2Fhome"]
        assert job["planned_tests_count"] == 6
        assert job["requests_used"] == 1

        tests = client.get(f"/api/scans/{scan_id}/tests").json()
        assert {item["plugin_id"] for item in tests} == {
            "safe-sql-injection",
            "safe-reflected-xss",
            "safe-open-redirect",
            "safe-cors-probe",
        }
        assert all(item["status"] == "preview" for item in tests)
        assert all(item["maximum_requests"] == 1 for item in tests)
        assert not any(item["destructive"] for item in tests)
        assert any("WHL_REFLECTION_PROBE" in item["exact_request_preview"] for item in tests)

        selected = [
            item["id"]
            for item in tests
            if item["mutation_type"]
            in {
                "sql_quote_append",
                "xss_inert_marker",
                "open_redirect_reserved_domain",
                "cors_reserved_origin",
            }
        ]
        approved = client.post(
            f"/api/scans/{scan_id}/approve-tests",
            json={
                "test_ids": selected,
                "authorization_confirmed": True,
                "confirmation_phrase": "APPROVE SELECTED SAFE TESTS",
            },
        )
        assert approved.status_code == 202, approved.text
        terminal = _wait_for_terminal(client, scan_id)
        assert terminal["status"] == "completed"
        assert terminal["requests_used"] == 5
        assert len(sender.calls) == 5
        assert sender.methods.count("OPTIONS") == 1

        completed_tests = client.get(f"/api/scans/{scan_id}/tests").json()
        approved_rows = [item for item in completed_tests if item["id"] in selected]
        assert all(item["status"] == "completed" for item in approved_rows)
        assert all(item["result_status"] in {"confirmed", "likely"} for item in approved_rows)
        assert sum(item["status"] == "preview" for item in completed_tests) == 2
        findings = client.get(f"/api/scans/{scan_id}/findings").json()
        analyzers = {item["analyzer"] for item in findings}
        assert {
            "safe-sql-injection",
            "safe-reflected-xss",
            "safe-open-redirect",
            "safe-cors-probe",
        } <= analyzers
        audits = client.get("/api/audit-events?limit=100").json()
        audit_types = {item["event_type"] for item in audits}
        assert "scan.tests_planned" in audit_types
        assert "scan.tests_approved" in audit_types
        assert "scan.test_completed" in audit_types


def test_ctf_scan_auto_registers_scope_and_runs_probes_unattended() -> None:
    with scanner_client(ctf_mode=True) as (client, sender):
        project_id, workspace_id = _prepare_target(client)
        # A host that was never added to scope: CTF mode must auto-register it.
        payload = _scan_payload(
            project_id,
            workspace_id,
            "https://ctf.example/?id=1&q=hello",
        )
        payload.update(
            {
                "profile": "ctf",
                "confirmation_phrase": "START CTF SCAN",
                "active_test_policy": {
                    "enabled": True,
                    "max_tests": 6,
                    "max_tests_per_parameter": 6,
                    "allow_limited_timing": False,
                },
            }
        )
        created = client.post(
            "/api/scans",
            json=payload,
            headers={"X-Correlation-ID": "ctf-scan-test"},
        )
        assert created.status_code == 202, created.text
        scan_id = created.json()["id"]

        terminal = _wait_for_terminal(client, scan_id)
        assert terminal["status"] == "completed", terminal
        # One crawl request plus the auto-approved probes, all sent without a manual step.
        assert terminal["requests_used"] >= 2
        assert sender.calls, "CTF probes were never sent"

        tests = client.get(f"/api/scans/{scan_id}/tests").json()
        assert tests, "CTF plan produced no probes"
        assert {item["plugin_id"] for item in tests} <= {
            "ctf-sql-injection",
            "ctf-reflected-xss",
            "ctf-path-traversal",
            "ctf-open-redirect",
        }
        # Every probe was auto-approved and executed; none waited for approval.
        assert all(item["status"] in {"completed", "blocked"} for item in tests)
        assert all(item["approved_at"] is not None for item in tests)

        findings = client.get(f"/api/scans/{scan_id}/findings").json()
        analyzers = {item["analyzer"] for item in findings}
        assert "ctf-sql-injection" in analyzers

        # The pasted target host was registered as an authorized scope rule.
        scope = client.get(f"/api/projects/{project_id}/scope").json()
        hostnames = {rule["hostname"] for rule in scope}
        assert "ctf.example" in hostnames

        audits = client.get("/api/audit-events?limit=200").json()
        audit_types = {item["event_type"] for item in audits}
        assert "scan.tests_approved" in audit_types
        assert "scan.test_completed" in audit_types


def test_ctf_scan_requires_ctf_mode_enabled() -> None:
    with scanner_client(ctf_mode=False) as (client, sender):
        project_id, workspace_id = _prepare_target(client)
        payload = _scan_payload(project_id, workspace_id, "https://authorized.example/?id=1")
        payload.update(
            {
                "profile": "ctf",
                "confirmation_phrase": "START CTF SCAN",
                "active_test_policy": {"enabled": True},
            }
        )
        blocked = client.post("/api/scans", json=payload)
        assert blocked.status_code == 403
        assert blocked.json()["code"] == "execution_blocked"
        assert sender.calls == []


def test_safe_test_approval_rejects_foreign_and_duplicate_ids() -> None:
    with scanner_client() as (client, _sender):
        project_id, workspace_id = _prepare_target(client)
        payload = _scan_payload(
            project_id,
            workspace_id,
            "https://authorized.example/?id=1",
        )
        payload.update(
            {
                "profile": "safe",
                "confirmation_phrase": "START SAFE SCAN",
                "active_test_policy": {"enabled": True, "max_tests": 2},
            }
        )
        created = client.post("/api/scans", json=payload)
        scan_id = created.json()["id"]
        for _ in range(600):
            if client.get(f"/api/scans/{scan_id}").json()["status"] == "waiting_for_approval":
                break
            time.sleep(0.01)
        tests = client.get(f"/api/scans/{scan_id}/tests").json()
        duplicate = client.post(
            f"/api/scans/{scan_id}/approve-tests",
            json={
                "test_ids": [tests[0]["id"], tests[0]["id"]],
                "authorization_confirmed": True,
                "confirmation_phrase": "APPROVE SELECTED SAFE TESTS",
            },
        )
        assert duplicate.status_code == 422
        foreign = client.post(
            f"/api/scans/{scan_id}/approve-tests",
            json={
                "test_ids": ["99999999-9999-4999-8999-999999999999"],
                "authorization_confirmed": True,
                "confirmation_phrase": "APPROVE SELECTED SAFE TESTS",
            },
        )
        assert foreign.status_code == 403
        cancelled = client.post(f"/api/scans/{scan_id}/cancel")
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"
        after_cancel = client.post(
            f"/api/scans/{scan_id}/approve-tests",
            json={
                "test_ids": [tests[0]["id"]],
                "authorization_confirmed": True,
                "confirmation_phrase": "APPROVE SELECTED SAFE TESTS",
            },
        )
        assert after_cancel.status_code == 409


def test_scanner_can_cancel_a_queued_job_before_first_request() -> None:
    with scanner_client() as (client, sender):
        project_id, workspace_id = _prepare_target(client)
        tasks = client.app.state.scan_tasks
        original_start = tasks.start
        captured: list[Coroutine[Any, Any, None]] = []

        def hold_task(scan_id: UUID, operation: Coroutine[Any, Any, None]) -> None:
            del scan_id
            captured.append(operation)

        tasks.start = hold_task
        try:
            created = client.post(
                "/api/scans",
                json=_scan_payload(
                    project_id,
                    workspace_id,
                    "https://authorized.example/",
                ),
            )
        finally:
            tasks.start = original_start
        assert created.status_code == 202
        scan_id = created.json()["id"]
        cancelled = client.post(f"/api/scans/{scan_id}/cancel")
        assert cancelled.status_code == 200
        assert cancelled.json()["cancellation_requested"] is True
        assert sender.calls == []
        for operation in captured:
            operation.close()


def test_passive_scan_collects_well_known_documents_and_stops_at_budget() -> None:
    with scanner_client() as (client, sender):
        project_id, workspace_id = _prepare_target(client)
        payload = _scan_payload(
            project_id,
            workspace_id,
            "https://authorized.example/",
        )
        payload["crawl_policy"] = {
            "max_depth": 2,
            "max_pages": 5,
            "max_requests": 5,
            "requests_per_second": 5,
            "concurrency": 1,
        }
        created = client.post("/api/scans", json=payload)
        assert created.status_code == 202, created.text
        scan_id = created.json()["id"]
        job = _wait_for_terminal(client, scan_id)
        assert job["status"] == "completed"
        assert job["requests_used"] == 5
        assert {value["name"] for value in job["fingerprints"]} >= {"scanner-test"}
        assert len(sender.calls) == 5

        endpoints = client.get(f"/api/scans/{scan_id}/endpoints").json()
        assert any(
            item["source"] == "robots_disallow" and item["url"].endswith("/admin")
            for item in endpoints
        )
        assert any(
            item["source"] == "sitemap" and "catalog?id=9" in item["url"] for item in endpoints
        )
        assert any(item["source"] == "openapi" and item["method"] == "POST" for item in endpoints)
        parameters = client.get(f"/api/scans/{scan_id}/parameters").json()
        assert any(item["source"] == "openapi" and item["name"] == "name" for item in parameters)
        events = client.get(f"/api/scans/{scan_id}/events").json()
        assert any("request budget" in item["message"] for item in events)

        listed = client.get(f"/api/scans?project_id={project_id}")
        assert listed.status_code == 200
        assert any(item["id"] == scan_id for item in listed.json())
        cannot_cancel = client.post(f"/api/scans/{scan_id}/cancel")
        assert cannot_cancel.status_code == 409


def test_scan_creation_rejects_browser_execution_missing_workspace_and_disabled_server() -> None:
    with scanner_client() as (client, sender):
        project_id, workspace_id = _prepare_target(client)
        javascript = _scan_payload(
            project_id,
            workspace_id,
            "https://authorized.example/",
        )
        javascript["crawl_policy"] = {
            "max_depth": 1,
            "max_pages": 1,
            "max_requests": 1,
            "execute_javascript": True,
        }
        blocked = client.post("/api/scans", json=javascript)
        assert blocked.status_code == 403

        missing = _scan_payload(
            project_id,
            "99999999-9999-4999-8999-999999999999",
            "https://authorized.example/",
        )
        missing_response = client.post("/api/scans", json=missing)
        assert missing_response.status_code == 404
        assert sender.calls == []

    settings = Settings(
        environment="test",
        database_url="sqlite+aiosqlite:///:memory:",
    )
    with TestClient(create_app(settings)) as disabled:
        response = disabled.post(
            "/api/scans",
            json=_scan_payload(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "https://authorized.example/",
            ),
        )
        assert response.status_code == 403


def test_scan_policy_is_reduced_to_remaining_workspace_budget() -> None:
    with scanner_client() as (client, _sender):
        project_id, workspace_id = _prepare_target(client)
        workspace = client.get(f"/api/workspaces/{workspace_id}").json()
        reduced = client.patch(
            f"/api/workspaces/{workspace_id}",
            json={"request_budget": 2, "version": workspace["version"]},
        )
        assert reduced.status_code == 200, reduced.text
        payload = _scan_payload(
            project_id,
            workspace_id,
            "https://authorized.example/",
        )
        payload["crawl_policy"] = {
            "max_depth": 2,
            "max_pages": 5,
            "max_requests": 5,
            "requests_per_second": 5,
            "concurrency": 1,
        }
        created = client.post("/api/scans", json=payload)
        assert created.status_code == 202, created.text
        assert created.json()["request_budget"] == 2
        assert created.json()["crawl_policy"]["max_pages"] == 2
        assert created.json()["crawl_policy"]["max_requests"] == 2
        assert created.json()["crawl_policy"]["requests_per_second"] == 2
        terminal = _wait_for_terminal(client, created.json()["id"])
        assert terminal["status"] == "completed"
        assert terminal["requests_used"] == 2

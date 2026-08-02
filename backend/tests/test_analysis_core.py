"""Passive analyzer, diff engine, persistence, and API tests."""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from webhacking_lab.analyzers.diff_analyzer import DiffAnalyzer
from webhacking_lab.analyzers.engine import AnalysisEngine
from webhacking_lab.analyzers.models import AnalysisContext
from webhacking_lab.http_client.models import NameValue
from webhacking_lab.http_client.request_normalizer import (
    normalize_request,
    normalize_response,
)


def _segment(value: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(value).encode()).decode()
    return encoded.rstrip("=")


@pytest.mark.asyncio
async def test_six_passive_analyzers_report_signals_without_confirmation() -> None:
    request = normalize_request(
        method="GET",
        url="https://app.example/search?q=hello&id=1",
        max_body_bytes=1024,
    )
    response = normalize_response(
        status_code=500,
        headers=[
            ("Content-Type", "text/html"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
            ("Set-Cookie", "session=value"),
        ],
        body="<p>hello</p> You have an error in your SQL syntax",
        max_body_bytes=4096,
    )
    results = await AnalysisEngine().analyze(request, response, AnalysisContext())
    by_category = {result.category.value: result for result in results}

    assert len(results) == 6
    assert by_category["cors"].status.value == "suspicious"
    assert by_category["xss"].status.value == "suspicious"
    assert by_category["sql_injection"].status.value == "likely"
    assert by_category["authentication"].status.value == "observation"
    assert all(result.status.value != "confirmed" for result in results)
    assert by_category["sql_injection"].safe_test_cases[0].destructive is False


@pytest.mark.asyncio
async def test_jwt_analyzer_decodes_structure_but_never_tests_signature() -> None:
    token = f"{_segment({'alg': 'none', 'typ': 'JWT'})}.{_segment({'sub': 'demo'})}."
    request = normalize_request(
        method="GET",
        url="https://app.example/",
        max_body_bytes=1024,
    ).model_copy(update={"query": [NameValue(name="value", value=token)]})
    results = await AnalysisEngine().analyze(request, None, AnalysisContext())
    jwt = next(result for result in results if result.category.value == "jwt")
    assert jwt.status.value == "suspicious"
    assert jwt.severity.value == "high"
    assert jwt.safe_test_cases == []
    assert any("signature" in limitation for limitation in jwt.limitations)


def test_diff_masks_dynamic_values_and_compares_json_html_and_errors() -> None:
    analyzer = DiffAnalyzer()
    baseline_json = normalize_response(
        status_code=200,
        headers=[("Content-Type", "application/json"), ("X-Version", "1")],
        body='{"id":"550e8400-e29b-41d4-a716-446655440000","name":"alpha"}',
        elapsed_ms=10,
        max_body_bytes=4096,
    )
    test_json = normalize_response(
        status_code=500,
        headers=[("Content-Type", "application/json"), ("X-Version", "2")],
        body=('{"id":"550e8400-e29b-41d4-a716-446655440001","name":"beta","error":"SQL syntax"}'),
        elapsed_ms=15,
        max_body_bytes=4096,
    )
    result = analyzer.compare(
        baseline_json,
        test_json,
        jsonpath_ignore=["$.id"],
    )
    assert result.status_changed is True
    assert result.elapsed_ms_delta == 5
    assert result.header_differences[0].name == "x-version"
    assert "sql_error" in result.error_patterns_added
    assert all(change.path != "$.id" for change in result.json_differences)

    baseline_html = normalize_response(
        status_code=200,
        headers=[("Content-Type", "text/html")],
        body='<main>same</main><span class="nonce">one</span>',
        max_body_bytes=4096,
    )
    test_html = normalize_response(
        status_code=200,
        headers=[("Content-Type", "text/html")],
        body='<main>same</main><span class="nonce">two</span>',
        max_body_bytes=4096,
    )
    html_result = analyzer.compare(
        baseline_html,
        test_html,
        css_selector_ignore=[".nonce", "[invalid"],
    )
    assert html_result.html_text_similarity == 1


def test_analysis_and_diff_api_persist_real_results(client: TestClient) -> None:
    project = client.post(
        "/api/projects",
        json={"name": "Passive demo", "mode": "local_lab"},
    ).json()
    workspace_id = project["workspaces"][0]["id"]
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://localhost/search?q=hello",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "text/html"}],
                        "content": {"text": "<p>hello</p>"},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "http://localhost/search?q=hello",
                        "headers": [],
                    },
                    "response": {
                        "status": 500,
                        "headers": [{"name": "Content-Type", "value": "text/html"}],
                        "content": {"text": "<p>hello</p> You have an error in your SQL syntax"},
                    },
                },
            ]
        }
    }
    imported = client.post(
        "/api/requests/import/har",
        json={"content": json.dumps(har), "workspace_id": workspace_id, "persist": True},
    )
    assert imported.status_code == 200, imported.text
    request_ids = imported.json()["request_ids"]
    baseline = client.get(f"/api/requests/{request_ids[0]}").json()["responses"][0]
    test = client.get(f"/api/requests/{request_ids[1]}").json()["responses"][0]

    compared = client.post(
        "/api/diff",
        json={
            "baseline_response_id": baseline["id"],
            "test_response_id": test["id"],
        },
    )
    assert compared.status_code == 200, compared.text
    assert compared.json()["result"]["status_changed"] is True
    assert "sql_error" in compared.json()["result"]["error_patterns_added"]

    analyzed = client.post(
        "/api/analysis",
        json={"request_id": request_ids[1], "response_id": test["id"]},
        headers={"X-Correlation-ID": "analysis-run"},
    )
    assert analyzed.status_code == 201, analyzed.text
    payload = analyzed.json()
    assert len(payload["results"]) == 6
    assert len(payload["flow"]["nodes"]) == 8
    assert client.get(f"/api/analysis/{payload['id']}").status_code == 200
    flow = client.get(f"/api/analysis/{payload['id']}/flow")
    assert flow.status_code == 200
    assert flow.json()["nodes"][0]["id"] == "normalize"
    audits = client.get("/api/audit-events?limit=30").json()
    assert any(event["event_type"] == "analysis.completed" for event in audits)


def test_analysis_api_rejects_unknown_relations(client: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.post("/api/analysis", json={"request_id": missing}).status_code == 404
    assert client.get(f"/api/analysis/{missing}").status_code == 404
    assert (
        client.post(
            "/api/diff",
            json={"baseline_response_id": missing, "test_response_id": missing},
        ).status_code
        == 404
    )

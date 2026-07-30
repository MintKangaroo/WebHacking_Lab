"""System endpoint contract tests."""

from fastapi.testclient import TestClient


def test_health_reports_safe_defaults(client: TestClient) -> None:
    response = client.get("/api/health", headers={"X-Correlation-ID": "test-correlation"})

    assert response.status_code == 200
    assert response.headers["X-Correlation-ID"] == "test-correlation"
    payload = response.json()
    assert payload["status"] == "healthy"
    assert payload["safety"]["mode"] == "Analysis Only"
    assert payload["safety"]["network_execution_enabled"] is False
    assert payload["safety"]["insecure_tls_allowed"] is False


def test_version_contract(client: TestClient) -> None:
    response = client.get("/api/version")

    assert response.status_code == 200
    assert response.json() == {
        "product": "WebHacking Lab",
        "package": "webhacking_lab",
        "version": "0.1.0",
        "api_version": "v1",
    }


def test_dashboard_is_api_backed_demo_data(client: TestClient) -> None:
    response = client.get("/api/dashboard/overview")

    assert response.status_code == 200
    payload = response.json()
    assert payload["demo_mode"] is True
    assert len(payload["metrics"]) == 5
    assert sum(item["count"] for item in payload["severity_distribution"]) == 21
    assert payload["recent_activity"][1]["status"] == "blocked"


def test_openapi_exposes_system_routes(client: TestClient) -> None:
    response = client.get("/api/openapi.json")

    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/api/health" in paths
    assert "/api/dashboard/overview" in paths

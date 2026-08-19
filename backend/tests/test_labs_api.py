"""API tests for the isolated training-lab catalog endpoint."""

from fastapi.testclient import TestClient


def test_lab_catalog_lists_the_sqli_lab_and_is_disabled_by_default(client: TestClient) -> None:
    response = client.get("/api/labs")
    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is False
    assert "intentionally vulnerable" in payload["warning"].lower()
    sqli = next(lab for lab in payload["labs"] if lab["id"] == "sqli")
    assert sqli["category"] == "sql_injection"
    assert sqli["base_url"] == "http://lab-sqli:5000"
    assert sqli["target_path"].startswith("/products")

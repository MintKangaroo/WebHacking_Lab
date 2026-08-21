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


def test_lab_catalog_lists_every_isolated_lab(client: TestClient) -> None:
    payload = client.get("/api/labs").json()
    by_id = {lab["id"]: lab for lab in payload["labs"]}
    expected = {
        "sqli": "sql_injection",
        "xss": "xss",
        "idor": "idor",
        "path-traversal": "path_traversal",
        "cmdi": "command_injection",
    }
    assert expected.items() <= {k: v["category"] for k, v in by_id.items()}.items()
    for lab in by_id.values():
        assert lab["base_url"].startswith("http://lab-")
        assert lab["objective"]
        assert lab["hint"]

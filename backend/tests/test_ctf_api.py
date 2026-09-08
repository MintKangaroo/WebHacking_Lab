"""CTF Workspace challenge-tracker API tests."""

from fastapi.testclient import TestClient


def _create(client: TestClient, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": "Baby SQLi",
        "event": "PicoCTF 2025",
        "category": "web",
        "difficulty": "easy",
        "points": 100,
        "target_url": "https://ctf.example/chal?id=1",
        "notes": "UNION-based, 3 columns.",
    }
    payload.update(overrides)
    response = client.post("/api/ctf/challenges", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_create_list_and_get_challenge(client: TestClient) -> None:
    created = _create(client)
    assert created["status"] == "todo"
    assert created["solved_at"] is None
    assert created["points"] == 100

    listed = client.get("/api/ctf/challenges").json()
    assert [item["id"] for item in listed] == [created["id"]]

    fetched = client.get(f"/api/ctf/challenges/{created['id']}").json()
    assert fetched["name"] == "Baby SQLi"
    assert fetched["target_url"] == "https://ctf.example/chal?id=1"


def test_solving_a_challenge_sets_and_clears_solved_at(client: TestClient) -> None:
    created = _create(client)
    solved = client.patch(
        f"/api/ctf/challenges/{created['id']}",
        json={"status": "solved", "flag": "picoCTF{demo}"},
    ).json()
    assert solved["status"] == "solved"
    assert solved["solved_at"] is not None
    assert solved["flag"] == "picoCTF{demo}"

    reopened = client.patch(
        f"/api/ctf/challenges/{created['id']}",
        json={"status": "in_progress"},
    ).json()
    assert reopened["status"] == "in_progress"
    assert reopened["solved_at"] is None


def test_list_filters_by_event(client: TestClient) -> None:
    _create(client, event="PicoCTF 2025", name="A")
    _create(client, event="HTB Cyber Apocalypse", name="B")

    only_pico = client.get("/api/ctf/challenges", params={"event": "PicoCTF 2025"}).json()
    assert [item["name"] for item in only_pico] == ["A"]


def test_delete_removes_the_challenge(client: TestClient) -> None:
    created = _create(client)
    deleted = client.delete(f"/api/ctf/challenges/{created['id']}")
    assert deleted.status_code == 204
    assert client.get("/api/ctf/challenges").json() == []
    assert client.get(f"/api/ctf/challenges/{created['id']}").status_code == 404


def test_validation_and_not_found(client: TestClient) -> None:
    # An empty name is rejected by the schema.
    assert client.post("/api/ctf/challenges", json={"name": ""}).status_code == 422
    # An unknown status value is rejected.
    created = _create(client)
    bad = client.patch(f"/api/ctf/challenges/{created['id']}", json={"status": "won"})
    assert bad.status_code == 422
    # A missing challenge returns 404.
    missing = client.get("/api/ctf/challenges/00000000-0000-4000-8000-000000000000")
    assert missing.status_code == 404

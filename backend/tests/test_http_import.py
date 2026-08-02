"""Safe cURL and HAR import tests."""

import json

import pytest

from webhacking_lab.domain.exceptions import ImportFormatError
from webhacking_lab.services.http_import import import_curl, import_har


def test_curl_import_is_data_only_and_redacts_authentication() -> None:
    request = import_curl(
        "curl -X POST 'http://127.0.0.1:5000/login?next=%2Fdashboard' "
        "-H 'Authorization: Bearer demo-secret' "
        "-H 'Content-Type: application/x-www-form-urlencoded' "
        "-b 'session=demo-cookie' --data 'username=learner&password=demo-pass'",
        max_body_bytes=4096,
    )

    assert request.method == "POST"
    assert request.path == "/login"
    assert request.query[0].value == "/dashboard"
    assert request.cookies[0].value == "[REDACTED]"
    assert "demo-secret" not in request.model_dump_json()
    assert "demo-pass" not in request.body


def test_curl_get_moves_data_to_query_and_head_is_supported() -> None:
    get_request = import_curl(
        "curl --get --data 'q=one&q=two' --url http://localhost/search",
        max_body_bytes=1024,
    )
    head_request = import_curl("curl -I http://localhost/", max_body_bytes=1024)

    assert [item.value for item in get_request.query] == ["one", "two"]
    assert get_request.body == ""
    assert head_request.method == "HEAD"


@pytest.mark.parametrize(
    "command",
    [
        "wget http://localhost/",
        "curl -k https://localhost/",
        "curl --proxy http://proxy.test http://localhost/",
        "curl --data @secret.txt http://localhost/",
        "curl --cookie @cookies.txt http://localhost/",
        "curl --unknown http://localhost/",
        "curl http://localhost/ http://other.local/",
        "curl 'unterminated",
    ],
)
def test_curl_import_rejects_unsafe_or_malformed_options(command: str) -> None:
    with pytest.raises(ImportFormatError):
        import_curl(command, max_body_bytes=1024)


def _har() -> str:
    return json.dumps(
        {
            "log": {
                "entries": [
                    {
                        "time": 19.5,
                        "request": {
                            "method": "POST",
                            "url": "http://localhost:5000/api/items?id=1&id=2",
                            "headers": [{"name": "X-API-Key", "value": "demo-key"}],
                            "cookies": [{"name": "session", "value": "demo-cookie"}],
                            "queryString": [
                                {"name": "id", "value": "1"},
                                {"name": "id", "value": "2"},
                            ],
                            "postData": {
                                "mimeType": "application/json",
                                "text": '{"password":"demo"}',
                            },
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [],
                            "cookies": [],
                            "content": {
                                "mimeType": "application/json",
                                "text": "eyJ0b2tlbiI6ImRlbW8ifQ==",
                                "encoding": "base64",
                            },
                        },
                    }
                ]
            }
        }
    )


def test_har_import_normalizes_request_and_response() -> None:
    exchanges = import_har(
        _har(),
        max_har_bytes=20_000,
        max_entries=5,
        max_request_bytes=4096,
        max_response_bytes=4096,
    )

    exchange = exchanges[0]
    assert [item.value for item in exchange.request.query] == ["1", "2"]
    assert exchange.request.headers[0].value == "[REDACTED]"
    assert exchange.response is not None
    assert exchange.response.elapsed_ms == 19.5
    assert exchange.response.reason == "OK"
    assert exchange.response.body == '{"token":"[REDACTED]"}'


def test_har_import_falls_back_to_url_query_when_query_string_is_omitted() -> None:
    document = json.loads(_har())
    request = document["log"]["entries"][0]["request"]
    request["url"] = "https://ctf.example/challenge/search?q=hello&q=again"
    request.pop("queryString")

    exchange = import_har(
        json.dumps(document),
        max_har_bytes=20_000,
        max_entries=5,
        max_request_bytes=4096,
        max_response_bytes=4096,
    )[0]

    assert [(item.name, item.value) for item in exchange.request.query] == [
        ("q", "hello"),
        ("q", "again"),
    ]


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        "{}",
        '{"log":{"entries":[null]}}',
        '{"log":{"entries":[{"request":{"method":"GET","url":""}}]}}',
    ],
)
def test_har_import_rejects_malformed_documents(payload: str) -> None:
    with pytest.raises(ImportFormatError):
        import_har(
            payload,
            max_har_bytes=4096,
            max_entries=5,
            max_request_bytes=1024,
            max_response_bytes=1024,
        )


def test_har_limits_entries_archive_and_invalid_base64() -> None:
    with pytest.raises(ImportFormatError, match="archive size"):
        import_har("{}", max_har_bytes=1, max_entries=1, max_request_bytes=1, max_response_bytes=1)
    with pytest.raises(ImportFormatError, match="too many"):
        import_har(
            '{"log":{"entries":[{},{}]}}',
            max_har_bytes=1024,
            max_entries=1,
            max_request_bytes=1024,
            max_response_bytes=1024,
        )
    invalid = json.loads(_har())
    invalid["log"]["entries"][0]["response"]["content"]["text"] = "***"
    with pytest.raises(ImportFormatError, match="base64"):
        import_har(
            json.dumps(invalid),
            max_har_bytes=20_000,
            max_entries=5,
            max_request_bytes=4096,
            max_response_bytes=4096,
        )

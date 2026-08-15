"""HTTP normalization and secret-redaction regression tests."""

import json

import pytest

from webhacking_lab.core.redaction import (
    REDACTED,
    redact_body,
    redact_cookie_string,
    redact_mapping,
    redact_pairs,
    redact_text,
    redact_value_shapes,
)
from webhacking_lab.domain.exceptions import ImportFormatError
from webhacking_lab.http_client.request_normalizer import (
    normalize_request,
    normalize_response,
    render_raw_request,
)


def test_request_normalization_preserves_multimap_and_masks_secrets() -> None:
    request = normalize_request(
        method="post",
        url="https://Example.COM:8443/search?q=first&q=second&token=query-secret",
        headers=[
            ("Authorization", "Bearer secret"),
            ("Cookie", "session=secret; theme=dark"),
            ("Content-Type", "application/json; charset=utf-8"),
        ],
        body=json.dumps({"username": "student", "password": "plain"}),
        max_body_bytes=4096,
    )

    assert request.method == "POST"
    assert request.host == "example.com"
    assert request.port == 8443
    assert [item.value for item in request.query if item.name == "q"] == ["first", "second"]
    assert next(item for item in request.query if item.name == "token").value == REDACTED
    assert next(item for item in request.headers if item.name == "Authorization").value == REDACTED
    assert request.cookies[0].value == REDACTED
    assert request.cookies[1].value == REDACTED
    assert json.loads(request.body)["password"] == REDACTED
    assert "plain" not in render_raw_request(request)
    assert "Bearer secret" not in render_raw_request(request)


def test_response_normalization_masks_cookie_and_computes_hash() -> None:
    response = normalize_response(
        status_code=200,
        headers=[("Set-Cookie", "session=secret; Path=/; HttpOnly")],
        body="api_key=secret-value",
        elapsed_ms=12.5,
        max_body_bytes=1024,
    )

    assert "secret" not in response.headers[0].value
    assert response.body == "api_key=[REDACTED]"
    assert len(response.body_hash) == 64
    assert response.body_hash == response.normalized_body_hash


def test_redaction_helpers_handle_nested_and_form_data() -> None:
    assert redact_mapping({"nested": {"access_token": "abc"}}) == {
        "nested": {"access_token": REDACTED}
    }
    assert redact_cookie_string("id=value; Path=/; SameSite=Lax") == (
        "id=[REDACTED]; Path=/; SameSite=Lax"
    )
    assert (
        redact_body(
            "username=student&password=secret",
            "application/x-www-form-urlencoded",
        )
        == "username=student&password=%5BREDACTED%5D"
    )
    pairs = redact_pairs([("X-API-Key", "secret"), ("Accept", "application/json")])
    assert [item.redacted for item in pairs] == [True, False]


_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_value_shape_secrets_are_masked_without_key_hints() -> None:
    # JWT under a benign JSON key (key-name masking would miss it).
    masked = redact_body(json.dumps({"data": _JWT}), "application/json")
    assert _JWT not in masked
    assert REDACTED in json.loads(masked)["data"]

    # Bearer credential embedded in free text keeps its scheme, drops the token.
    assert redact_text("Authorization: Bearer abc123def456ghi789") == (
        "Authorization: Bearer [REDACTED]"
    )

    # A long, high-entropy, mixed run reads as a credential.
    high_entropy = "aB3xK9mQ2pL7wZ4vR8tN6yU1cE5dF0gH2jK4lM6n"
    assert redact_value_shapes(f"key {high_entropy} tail") == "key [REDACTED] tail"


def test_value_shape_detection_leaves_ordinary_values_intact() -> None:
    # Short values and low-entropy prose must survive for analysis.
    assert redact_value_shapes("the quick brown fox jumps over the lazy dog") == (
        "the quick brown fox jumps over the lazy dog"
    )
    # A long all-lowercase run without digits is not treated as a secret.
    plain = "thequickbrownfoxjumpsoverthelazydogandthen"
    assert redact_value_shapes(plain) == plain
    # Benign JSON scalars pass through untouched.
    assert redact_mapping({"username": "student", "count": 42}) == {
        "username": "student",
        "count": 42,
    }


def test_query_value_shape_secret_is_masked_by_pairs() -> None:
    pairs = redact_pairs([("redirect", f"https://x/#{_JWT}")])
    assert _JWT not in pairs[0].value
    assert pairs[0].redacted is True


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("file:///etc/passwd", "Only http and https"),
        ("http://user:pass@example.test/", "user information"),
        ("http://example.test:99999/", "invalid port"),
        ("http:///missing", "hostname"),
    ],
)
def test_request_normalization_rejects_malformed_urls(url: str, message: str) -> None:
    with pytest.raises(ImportFormatError, match=message):
        normalize_request(method="GET", url=url, max_body_bytes=1024)


def test_request_and_response_limits_are_enforced() -> None:
    with pytest.raises(ImportFormatError, match="Request body exceeds"):
        normalize_request(
            method="POST",
            url="http://localhost/",
            body="too large",
            max_body_bytes=3,
        )
    with pytest.raises(ImportFormatError, match="Response body exceeds"):
        normalize_response(status_code=200, body="too large", max_body_bytes=3)


def test_ipv6_authorities_are_rendered_with_brackets() -> None:
    request = normalize_request(method="GET", url="http://[::1]:5000/path", max_body_bytes=1024)
    assert request.url == "http://[::1]:5000/path"
    assert "Host: [::1]:5000" in render_raw_request(request)

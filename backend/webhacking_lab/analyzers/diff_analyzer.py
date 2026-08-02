"""Noise-aware structured response comparison."""

import json
import re
from difflib import SequenceMatcher, unified_diff
from typing import Any

from bs4 import BeautifulSoup
from pydantic import BaseModel, ConfigDict, Field
from soupsieve.util import SelectorSyntaxError

from webhacking_lab.http_client.models import NameValue, NormalizedResponse

UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
TOKEN_PATTERN = re.compile(r"(?i)(csrf|nonce)([\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9_-]{12,}")


class DiffModel(BaseModel):
    """Strict diff artifact base."""

    model_config = ConfigDict(extra="forbid")


class HeaderDifference(DiffModel):
    """One case-insensitive multivalue header change."""

    name: str
    baseline: list[str]
    test: list[str]


class JsonDifference(DiffModel):
    """One changed flattened JSON path."""

    path: str
    baseline: Any = None
    test: Any = None


class ResponseDiff(DiffModel):
    """Bounded status, header, body, JSON, HTML, timing, and redirect comparison."""

    status_changed: bool
    baseline_status: int
    test_status: int
    header_differences: list[HeaderDifference]
    cookie_changed: bool
    body_similarity: float = Field(ge=0, le=1)
    body_size_delta: int
    elapsed_ms_delta: float | None
    redirect_changed: bool
    json_differences: list[JsonDifference]
    html_text_similarity: float | None = Field(default=None, ge=0, le=1)
    error_patterns_added: list[str]
    unified_body_diff: str


def _header_map(values: list[NameValue]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for item in values:
        result.setdefault(item.name.lower(), []).append(item.value)
    return result


def _normalize_dynamic(value: str, ignore_patterns: list[str]) -> str:
    normalized = UUID_PATTERN.sub("<UUID>", value)
    normalized = TIMESTAMP_PATTERN.sub("<TIMESTAMP>", normalized)
    normalized = TOKEN_PATTERN.sub(r"\1\2<TOKEN>", normalized)
    for pattern in ignore_patterns:
        try:
            normalized = re.sub(pattern, "<IGNORED>", normalized)
        except re.error:
            continue
    return normalized


def _flatten_json(value: Any, prefix: str = "$") -> dict[str, Any]:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key in sorted(value):
            result.update(_flatten_json(value[key], f"{prefix}.{key}"))
        return result
    if isinstance(value, list):
        result = {}
        for index, item in enumerate(value):
            result.update(_flatten_json(item, f"{prefix}[{index}]"))
        return result
    return {prefix: value}


def _json_differences(
    baseline: str,
    test: str,
    ignored_paths: set[str],
) -> list[JsonDifference]:
    try:
        baseline_flat = _flatten_json(json.loads(baseline))
        test_flat = _flatten_json(json.loads(test))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    paths = sorted((set(baseline_flat) | set(test_flat)) - ignored_paths)
    return [
        JsonDifference(path=path, baseline=baseline_flat.get(path), test=test_flat.get(path))
        for path in paths
        if baseline_flat.get(path) != test_flat.get(path)
    ][:200]


def _html_text(body: str, ignored_selectors: list[str]) -> str:
    soup = BeautifulSoup(body, "lxml")
    for selector in ignored_selectors:
        try:
            selected = soup.select(selector)
        except SelectorSyntaxError:
            continue
        for element in selected:
            element.decompose()
    return " ".join(soup.get_text(" ", strip=True).split())


ERROR_PATTERNS = {
    "sql_error": re.compile(r"(?i)(sql syntax|sqlite.*error|postgresql|ora-\d{5})"),
    "stack_trace": re.compile(r"(?i)(traceback \(most recent call last\)|stack trace)"),
    "template_error": re.compile(r"(?i)(template syntax error|undefinederror)"),
}


class DiffAnalyzer:
    """Compare two redacted responses while masking common dynamic noise."""

    def compare(
        self,
        baseline: NormalizedResponse,
        test: NormalizedResponse,
        *,
        ignore_patterns: list[str] | None = None,
        jsonpath_ignore: list[str] | None = None,
        css_selector_ignore: list[str] | None = None,
    ) -> ResponseDiff:
        """Return a bounded structured comparison."""

        patterns = ignore_patterns or []
        baseline_body = _normalize_dynamic(baseline.body, patterns)
        test_body = _normalize_dynamic(test.body, patterns)
        baseline_headers = _header_map(baseline.headers)
        test_headers = _header_map(test.headers)
        header_names = sorted(set(baseline_headers) | set(test_headers))
        header_diff = [
            HeaderDifference(
                name=name,
                baseline=baseline_headers.get(name, []),
                test=test_headers.get(name, []),
            )
            for name in header_names
            if baseline_headers.get(name, []) != test_headers.get(name, [])
        ]
        content_types = {baseline.content_type or "", test.content_type or ""}
        html_similarity = None
        if any("html" in value for value in content_types):
            baseline_html = _html_text(baseline_body, css_selector_ignore or [])
            test_html = _html_text(test_body, css_selector_ignore or [])
            html_similarity = SequenceMatcher(None, baseline_html, test_html).ratio()
        added_errors = [
            name
            for name, pattern in ERROR_PATTERNS.items()
            if pattern.search(test_body) and not pattern.search(baseline_body)
        ]
        diff_lines = unified_diff(
            baseline_body.splitlines(),
            test_body.splitlines(),
            fromfile="baseline",
            tofile="test",
            lineterm="",
            n=2,
        )
        elapsed_delta = None
        if baseline.elapsed_ms is not None and test.elapsed_ms is not None:
            elapsed_delta = test.elapsed_ms - baseline.elapsed_ms
        return ResponseDiff(
            status_changed=baseline.status_code != test.status_code,
            baseline_status=baseline.status_code,
            test_status=test.status_code,
            header_differences=header_diff,
            cookie_changed=baseline.cookies != test.cookies,
            body_similarity=SequenceMatcher(None, baseline_body, test_body).ratio(),
            body_size_delta=len(test.body.encode()) - len(baseline.body.encode()),
            elapsed_ms_delta=elapsed_delta,
            redirect_changed=baseline.redirect_history != test.redirect_history,
            json_differences=_json_differences(
                baseline_body,
                test_body,
                set(jsonpath_ignore or []),
            ),
            html_text_similarity=html_similarity,
            error_patterns_added=added_errors,
            unified_body_diff="\n".join(list(diff_lines)[:200]),
        )

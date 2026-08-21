"""Regression tests for inert JavaScript/Express source-to-sink analysis."""

from pathlib import Path

from webhacking_lab.domain.enums import (
    Severity,
    StaticFindingStatus,
    VulnerabilityCategory,
)
from webhacking_lab.static_analysis.languages.javascript.parser import (
    analyze_javascript_taint,
    extract_express_routes,
)
from webhacking_lab.static_analysis.models import IndexedFile
from webhacking_lab.static_analysis.route_extractor import extract_routes
from webhacking_lab.static_analysis.taint_engine import analyze_static_data_flows


def _analyze(source: str) -> dict[VulnerabilityCategory, object]:
    findings, _safe = analyze_javascript_taint(source, "app.js", [])
    return {finding.category: finding for finding in findings}


def test_sql_injection_through_template_literal_and_variable() -> None:
    source = (
        "app.get('/p', (req, res) => {\n"
        "  const id = req.query.id;\n"
        "  db.query(`SELECT * FROM p WHERE id = ${id}`);\n"
        "});\n"
    )
    finding = _analyze(source)[VulnerabilityCategory.SQL_INJECTION]
    assert finding.status == StaticFindingStatus.STATIC_CANDIDATE
    assert finding.severity == Severity.HIGH
    assert finding.parameter == "id"
    assert finding.sink_label == "query"


def test_reflected_xss_is_a_medium_candidate() -> None:
    source = "app.get('/s', (req, res) => { res.send('<p>' + req.query.q + '</p>'); });\n"
    finding = _analyze(source)[VulnerabilityCategory.XSS]
    assert finding.severity == Severity.MEDIUM
    assert finding.parameter == "q"
    assert finding.sink_label == "res.send"


def test_command_injection_via_child_process_method() -> None:
    source = "app.get('/ping', (req, res) => { cp.exec('ping ' + req.query.host); });\n"
    finding = _analyze(source)[VulnerabilityCategory.COMMAND_INJECTION]
    assert finding.status == StaticFindingStatus.STATIC_CANDIDATE
    assert finding.parameter == "host"
    assert finding.sink_label == "exec"


def test_path_traversal_via_fs_read() -> None:
    source = "app.get('/d', (req, res) => { fs.readFileSync(req.query.file); });\n"
    finding = _analyze(source)[VulnerabilityCategory.PATH_TRAVERSAL]
    assert finding.sink_label == "fs.readFileSync"
    assert finding.parameter == "file"


def test_open_redirect_from_request_input() -> None:
    source = "app.get('/go', (req, res) => { res.redirect(req.query.next); });\n"
    finding = _analyze(source)[VulnerabilityCategory.OPEN_REDIRECT]
    assert finding.severity == Severity.MEDIUM
    assert finding.sink_label == "res.redirect"


def test_request_header_getter_is_a_source() -> None:
    source = "app.get('/h', (req, res) => { res.send(req.get('x-name')); });\n"
    finding = _analyze(source)[VulnerabilityCategory.XSS]
    assert finding.parameter == "x-name"


def test_parseint_sanitizer_suppresses_sql_candidate() -> None:
    source = (
        "app.get('/p', (req, res) => {\n"
        "  const id = parseInt(req.query.id, 10);\n"
        "  db.query('SELECT * FROM t WHERE id = ' + id);\n"
        "});\n"
    )
    findings, safe = analyze_javascript_taint(source, "app.js", [])
    assert VulnerabilityCategory.SQL_INJECTION not in {f.category for f in findings}
    assert any("received a sanitized value" in note for note in safe)


def test_untainted_sink_yields_no_finding() -> None:
    source = "app.get('/x', (req, res) => { db.query('SELECT 1'); });\n"
    findings, _safe = analyze_javascript_taint(source, "app.js", [])
    assert findings == []


def test_express_route_extraction_paths_methods_and_params() -> None:
    source = (
        "app.get('/users/:userId', requireAuth, (req, res) => {});\n"
        "router.post('/items', (req, res) => {});\n"
        "app.all('/any', (req, res) => {});\n"
    )
    routes = {route.path: route for route in extract_express_routes(source, "app.js")}
    users = routes["/users/:userId"]
    assert users.framework == "Express"
    assert users.methods == ["GET"]
    assert [p.name for p in users.parameters] == ["userId"]
    assert users.authentication.required is True
    assert routes["/items"].methods == ["POST"]
    assert routes["/items"].authentication.required is False
    assert set(routes["/any"].methods) == {"GET", "POST", "PUT", "PATCH", "DELETE"}


def _indexed(path: str, language: str, size: int) -> IndexedFile:
    return IndexedFile(
        relative_path=path,
        language=language,
        size_bytes=size,
        sha256="0" * 64,
        secret_findings=[],
        warning_codes=[],
    )


def test_taint_engine_routes_javascript_files(tmp_path: Path) -> None:
    source = "app.get('/p', (req, res) => { db.query('SELECT ' + req.query.id); });\n"
    (tmp_path / "app.js").write_text(source, encoding="utf-8")
    result = analyze_static_data_flows(
        tmp_path,
        [_indexed("app.js", "javascript", len(source))],
        [],
    )
    categories = {finding.category for finding in result.findings}
    assert VulnerabilityCategory.SQL_INJECTION in categories


def test_route_extractor_emits_express_routes_only_when_detected(tmp_path: Path) -> None:
    source = "app.get('/p/:id', (req, res) => {});\n"
    (tmp_path / "app.js").write_text(source, encoding="utf-8")
    files = [_indexed("app.js", "javascript", len(source))]

    with_express = extract_routes(tmp_path, files, ["Express"])
    assert any(route.path == "/p/:id" for route in with_express.routes)

    without = extract_routes(tmp_path, files, [])
    assert without.routes == []

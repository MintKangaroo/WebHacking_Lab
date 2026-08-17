"""Regression tests for inert Python and PHP source-to-sink analysis."""

from pathlib import Path

import pytest

from webhacking_lab.domain.enums import StaticFindingStatus, VulnerabilityCategory
from webhacking_lab.static_analysis.languages.php.parser import (
    _outer_call_name,
    analyze_php_taint,
)
from webhacking_lab.static_analysis.languages.python.taint_rules import (
    MAX_CALL_DEPTH,
    analyze_python_taint,
)
from webhacking_lab.static_analysis.models import (
    AuthenticationInfo,
    ExtractedRoute,
    IndexedFile,
    StaticParameter,
)
from webhacking_lab.static_analysis.taint_engine import (
    MAX_TAINT_FILE_BYTES,
    analyze_static_data_flows,
)


def _route(file_path: str, handler: str = "handler") -> ExtractedRoute:
    return ExtractedRoute(
        file_path=file_path,
        framework="Plain PHP" if file_path.endswith(".php") else "Flask",
        methods=["GET"],
        path="/test",
        handler_name=handler,
        line_start=1,
        line_end=20,
        parameters=[],
        authentication=AuthenticationInfo(),
    )


def _indexed(relative_path: str, language: str, size_bytes: int) -> IndexedFile:
    return IndexedFile(
        relative_path=relative_path,
        language=language,
        size_bytes=size_bytes,
        sha256="0" * 64,
        secret_findings=[],
        warning_codes=[],
    )


def test_flask_sql_injection_flow_and_parameterized_query() -> None:
    vulnerable = """
def product():
    item_id = request.args["id"]
    query = f"SELECT * FROM products WHERE id = {item_id}"
    return cursor.execute(query)
"""
    findings, _ = analyze_python_taint(vulnerable, "app.py", [_route("app.py", "product")])
    finding = findings[0]
    assert finding.category == VulnerabilityCategory.SQL_INJECTION
    assert finding.parameter == "id"
    assert finding.source_line == 3
    assert finding.sink_line == 5
    assert [step.kind for step in finding.flow_steps] == [
        "source",
        "transformation",
        "transformation",
        "transformation",
        "sink",
    ]
    assert finding.status == StaticFindingStatus.STATIC_CANDIDATE

    safe = """
def product():
    item_id = request.args["id"]
    return cursor.execute("SELECT * FROM products WHERE id = ?", (item_id,))
"""
    safe_findings, _ = analyze_python_taint(safe, "app.py", [_route("app.py", "product")])
    assert safe_findings == []


def test_flask_ssti_command_and_path_traversal_flows() -> None:
    source = """
def handler():
    template = request.form.get("template")
    render_template_string(template)
    host = request.args.get("host")
    subprocess.run("ping " + host, shell=True)
    name = request.args.get("name")
    return send_file("/srv/files/" + name)
"""
    findings, _ = analyze_python_taint(source, "app.py", [_route("app.py")])
    assert {finding.category for finding in findings} == {
        VulnerabilityCategory.SERVER_SIDE_TEMPLATE_INJECTION,
        VulnerabilityCategory.COMMAND_INJECTION,
        VulnerabilityCategory.PATH_TRAVERSAL,
    }
    assert {finding.parameter for finding in findings} == {"template", "host", "name"}


def test_flask_strong_sanitizer_suppresses_sql_candidate() -> None:
    source = """
def handler():
    item_id = int(request.args.get("id"))
    return cursor.execute(f"SELECT * FROM items WHERE id = {item_id}")
"""
    findings, safe_decisions = analyze_python_taint(source, "app.py", [_route("app.py")])
    assert findings == []
    assert "strongly sanitized" in safe_decisions[0]


def test_python_mixed_sanitized_and_raw_inputs_remain_a_candidate() -> None:
    source = """
def handler():
    numeric_id = int(request.args.get("id"))
    raw_sort = request.args.get("sort")
    query = f"SELECT * FROM items WHERE id = {numeric_id} ORDER BY {raw_sort}"
    return cursor.execute(query)
"""
    findings, _ = analyze_python_taint(source, "app.py", [_route("app.py")])
    assert len(findings) == 1
    assert findings[0].category == VulnerabilityCategory.SQL_INJECTION
    assert findings[0].status == StaticFindingStatus.STATIC_CANDIDATE
    assert findings[0].sanitizers == []


def test_python_flow_steps_are_bounded() -> None:
    assignments = ["    value = request.args.get('q')"]
    previous = "value"
    for index in range(100):
        assignments.append(f"    value_{index} = {previous}")
        previous = f"value_{index}"
    assignments.append("    return cursor.execute(value_99)")
    source = "def handler():\n" + "\n".join(assignments)
    findings, _ = analyze_python_taint(source, "app.py", [_route("app.py")])
    assert len(findings[0].flow_steps) == 64
    assert "capped at 64 steps" in findings[0].limitations[-1]


def test_python_tainted_argument_reaches_sink_in_local_helper() -> None:
    source = """
def handler():
    q = request.args["q"]
    run_query(q)


def run_query(value):
    cursor.execute("SELECT * FROM t WHERE x = " + value)
"""
    findings, _ = analyze_python_taint(source, "app.py", [_route("app.py")])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == VulnerabilityCategory.SQL_INJECTION
    assert finding.parameter == "q"
    assert finding.route_handler == "handler"
    assert finding.sink_line == 8  # inside the helper, not the handler
    assert any(step.label == "Argument to value" for step in finding.flow_steps)
    assert "Traced across 1 local function call" in finding.limitations[-1]


def test_python_path_parameter_flows_into_helper_sink() -> None:
    source = """
def handler(name):
    render_it(name)


def render_it(value):
    return make_response(value)
"""
    route = _route("app.py")
    route.parameters.append(StaticParameter(name="name", location="path"))
    findings, _ = analyze_python_taint(source, "app.py", [route])
    assert [f.category for f in findings] == [VulnerabilityCategory.XSS]
    assert findings[0].sink_line == 7  # inside render_it, reached from the path param


def test_python_strong_sanitizer_before_helper_call_is_safe() -> None:
    source = """
def handler():
    q = int(request.args["q"])
    run_query(q)


def run_query(value):
    cursor.execute("SELECT * FROM t WHERE x = " + str(value))
"""
    findings, safe = analyze_python_taint(source, "app.py", [_route("app.py")])
    assert findings == []
    assert len(safe) == 1


def test_python_untainted_helper_argument_yields_no_finding() -> None:
    source = """
def handler():
    run_query("constant")


def run_query(value):
    cursor.execute(value)
"""
    findings, _ = analyze_python_taint(source, "app.py", [_route("app.py")])
    assert findings == []


def test_python_cross_function_recursion_terminates_and_is_bounded() -> None:
    # Mutual recursion must be cycle-guarded; a chain longer than the depth
    # budget must stop rather than recurse without bound.
    recursive = """
def handler():
    step_a(request.args["q"])


def step_a(x):
    step_b(x)


def step_b(y):
    step_a(y)
    cursor.execute(y)
"""
    findings, _ = analyze_python_taint(recursive, "app.py", [_route("app.py")])
    assert len(findings) == 1

    levels = ["def handler():\n    level_0(request.args['q'])"]
    for index in range(MAX_CALL_DEPTH + 3):
        nxt = f"level_{index + 1}(x)" if index < MAX_CALL_DEPTH + 2 else "cursor.execute(x)"
        levels.append(f"def level_{index}(x):\n    {nxt}")
    deep_source = "\n\n\n".join(levels)
    deep_findings, _ = analyze_python_taint(deep_source, "app.py", [_route("app.py")])
    # The sink sits below the call-depth budget, so it is intentionally not reached.
    assert deep_findings == []


def test_php_superglobal_sql_and_include_flows() -> None:
    source = """<?php
$id = $_GET["id"];
$query = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $query);
$page = $_GET["page"];
include($page);
"""
    findings, _ = analyze_php_taint(source, "public/index.php", [_route("public/index.php")])
    assert {finding.category for finding in findings} == {
        VulnerabilityCategory.SQL_INJECTION,
        VulnerabilityCategory.FILE_INCLUSION,
    }
    sql = next(
        finding for finding in findings if finding.category == VulnerabilityCategory.SQL_INJECTION
    )
    assert sql.source_line == 2
    assert sql.sink_line == 4
    assert sql.parameter == "id"


def test_php_prepared_statement_and_html_escaping_are_safe() -> None:
    source = """<?php
$id = $_GET["id"];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$name = htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");
echo $name;
"""
    findings, safe_decisions = analyze_php_taint(source, "index.php", [_route("index.php")])
    assert findings == []
    assert any("prepared statement" in decision for decision in safe_decisions)
    assert any("sanitized value" in decision for decision in safe_decisions)


def test_php_mixed_sanitized_and_raw_output_remains_a_candidate() -> None:
    source = """<?php
$safe = htmlspecialchars($_GET["safe"], ENT_QUOTES, "UTF-8");
$raw = $_GET["raw"];
echo $safe . $raw;
"""
    findings, _ = analyze_php_taint(source, "index.php", [_route("index.php")])
    assert len(findings) == 1
    assert findings[0].category == VulnerabilityCategory.XSS
    assert findings[0].status == StaticFindingStatus.STATIC_CANDIDATE
    assert findings[0].sanitizers == []


def test_php_comment_stripping_preserves_strings_and_line_evidence() -> None:
    source = """<?php
// line comment with echo $_GET["ignored"];
# hash comment with system($_GET["ignored"]);
/* block comment
with include($_GET["ignored"]); */
$literal = "escaped \\" quote; // still a string";
$raw = $_GET["q"];
echo $raw;
"""
    findings, _ = analyze_php_taint(source, "index.php", [_route("index.php")])
    assert len(findings) == 1
    assert findings[0].parameter == "q"
    assert findings[0].source_line == 7
    assert findings[0].sink_line == 8


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("not a call", None),
        ('htmlspecialchars("escaped \\" value")', "htmlspecialchars"),
        ("htmlspecialchars(trim($value))", "htmlspecialchars"),
        ("htmlspecialchars($value) . trim($raw)", None),
        ("htmlspecialchars(($value)", None),
    ],
)
def test_php_outer_sanitizer_requires_one_complete_call(
    expression: str,
    expected: str | None,
) -> None:
    assert _outer_call_name(expression) == expected


def test_php_flow_steps_are_bounded() -> None:
    statements = ['$value = $_GET["q"]']
    previous = "$value"
    for index in range(100):
        statements.append(f"$value_{index} = {previous}")
        previous = f"$value_{index}"
    statements.append("echo $value_99")
    source = "<?php\n" + ";\n".join(statements) + ";"
    findings, _ = analyze_php_taint(source, "index.php", [_route("index.php")])
    assert len(findings[0].flow_steps) == 64
    assert "capped at 64 steps" in findings[0].limitations[-1]


def test_taint_coordinator_warns_for_oversized_and_malformed_files(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.py"
    malformed.write_text("def broken(", encoding="utf-8")
    result = analyze_static_data_flows(
        tmp_path,
        [
            _indexed("ignored.js", "javascript", 10),
            _indexed("oversized.py", "python", MAX_TAINT_FILE_BYTES + 1),
            _indexed("malformed.py", "python", malformed.stat().st_size),
        ],
        [],
    )
    assert result.findings == []
    assert result.warnings == [
        "Skipped malformed python taint input: malformed.py (SyntaxError)",
        "Skipped oversized taint input: oversized.py",
    ]


def test_taint_coordinator_caps_project_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "app.py"
    source.write_text("def handler():\n    pass\n", encoding="utf-8")
    sample_source = """
def handler():
    value = request.args.get("q")
    return cursor.execute(value)
"""
    sample, _ = analyze_python_taint(sample_source, "app.py", [_route("app.py")])
    monkeypatch.setattr(
        "webhacking_lab.static_analysis.taint_engine.analyze_python_taint",
        lambda *_args: (sample * 500, ["bounded safe decision"]),
    )
    result = analyze_static_data_flows(
        tmp_path,
        [_indexed("app.py", "python", source.stat().st_size)],
        [_route("app.py")],
    )
    assert len(result.findings) == 500
    assert result.safe_decisions == ["bounded safe decision"]
    assert result.warnings == ["Static finding budget reached; remaining files were not analyzed"]

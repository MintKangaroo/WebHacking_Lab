"""Bounded intra-procedural Python taint analysis using the inert built-in AST."""

import ast
from dataclasses import dataclass
from typing import Literal

from webhacking_lab.domain.enums import (
    Severity,
    StaticFindingStatus,
    VulnerabilityCategory,
)
from webhacking_lab.static_analysis.models import (
    ExtractedRoute,
    ExtractedStaticFinding,
    StaticFlowStep,
    StaticRemediation,
)

REQUEST_LOCATIONS = {
    "args": "query",
    "form": "form",
    "values": "request",
    "json": "json",
    "headers": "header",
    "cookies": "cookie",
    "files": "multipart",
}
SANITIZERS = {
    "int": "integer conversion",
    "float": "numeric conversion",
    "uuid.UUID": "UUID validation",
    "escape": "HTML escaping",
    "html.escape": "HTML escaping",
    "markupsafe.escape": "HTML escaping",
    "secure_filename": "filename normalization",
    "werkzeug.utils.secure_filename": "filename normalization",
    "basename": "basename normalization",
    "os.path.basename": "basename normalization",
}
STRONG_SANITIZERS = {
    VulnerabilityCategory.SQL_INJECTION: {
        "integer conversion",
        "numeric conversion",
        "UUID validation",
    },
    VulnerabilityCategory.XSS: {"HTML escaping"},
}
CATEGORY_NAMES = {
    VulnerabilityCategory.SQL_INJECTION: "SQL Injection",
    VulnerabilityCategory.XSS: "Cross-Site Scripting",
    VulnerabilityCategory.COMMAND_INJECTION: "Command Injection",
    VulnerabilityCategory.SERVER_SIDE_TEMPLATE_INJECTION: "Server-Side Template Injection",
    VulnerabilityCategory.PATH_TRAVERSAL: "Path Traversal",
}
MAX_FLOW_STEPS = 64


@dataclass(frozen=True)
class _Taint:
    steps: tuple[StaticFlowStep, ...]
    parameter: str | None
    sanitizers: frozenset[str] = frozenset()
    truncated: bool = False

    def append(
        self,
        kind: Literal["source", "transformation", "sanitizer", "sink"],
        label: str,
        line: int,
        detail: str,
    ) -> "_Taint":
        sanitizers = self.sanitizers | ({label} if kind == "sanitizer" else set())
        if kind != "sink" and len(self.steps) >= MAX_FLOW_STEPS - 1:
            return _Taint(self.steps, self.parameter, frozenset(sanitizers), True)
        steps = self.steps[: MAX_FLOW_STEPS - 1] if kind == "sink" else self.steps
        step = StaticFlowStep(
            id=f"step-{len(steps)}",
            kind=kind,
            label=label,
            line=line,
            detail=detail,
        )
        return _Taint(
            (*steps, step),
            self.parameter,
            frozenset(sanitizers),
            self.truncated or len(self.steps) > len(steps),
        )


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _string_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _source_from_container(container: ast.AST, key: str | None, line: int) -> _Taint | None:
    location = ""
    if isinstance(container, ast.Attribute) and _name(container.value) == "request":
        location = REQUEST_LOCATIONS.get(container.attr, "")
    elif isinstance(container, ast.Call) and _name(container.func) == "request.get_json":
        location = "json"
    if not location:
        return None
    parameter = key or location
    label = f"request.{location}[{parameter!r}]"
    return _Taint(
        (
            StaticFlowStep(
                id="step-0",
                kind="source",
                label=label,
                line=line,
                detail=f"Untrusted {location} input enters the route handler.",
            ),
        ),
        parameter,
    )


def _request_source(node: ast.AST) -> _Taint | None:
    line = getattr(node, "lineno", 1)
    if isinstance(node, ast.Subscript):
        return _source_from_container(node.value, _string_key(node.slice), line)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            key = _string_key(node.args[0]) if node.args else None
            return _source_from_container(node.func.value, key, line)
        if _name(node.func) == "request.get_json":
            return _source_from_container(node, None, line)
    if isinstance(node, ast.Attribute) and _name(node.value) == "request":
        return _source_from_container(node, None, line)
    return None


def _merge(values: list[_Taint | None]) -> _Taint | None:
    tainted = [value for value in values if value is not None]
    if not tainted:
        return None
    first = tainted[0]
    sanitizers = set(first.sanitizers)
    for value in tainted[1:]:
        sanitizers.intersection_update(value.sanitizers)
    return _Taint(
        first.steps,
        first.parameter,
        frozenset(sanitizers),
        any(value.truncated for value in tainted),
    )


def _trace(node: ast.AST, environment: dict[str, _Taint]) -> _Taint | None:
    source = _request_source(node)
    if source is not None:
        return source
    if isinstance(node, ast.Name):
        return environment.get(node.id)
    if isinstance(node, ast.Attribute):
        return _trace(node.value, environment)
    if isinstance(node, ast.Subscript):
        return _trace(node.value, environment)
    if isinstance(node, ast.BinOp):
        value = _merge([_trace(node.left, environment), _trace(node.right, environment)])
        return (
            value.append(
                "transformation",
                "String concatenation",
                node.lineno,
                "Tainted data is combined into another value.",
            )
            if value is not None
            else None
        )
    if isinstance(node, ast.JoinedStr):
        value = _merge(
            [
                _trace(item.value, environment)
                for item in node.values
                if isinstance(item, ast.FormattedValue)
            ]
        )
        return (
            value.append(
                "transformation",
                "f-string interpolation",
                node.lineno,
                "Tainted data is interpolated into a string.",
            )
            if value is not None
            else None
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return _merge([_trace(item, environment) for item in node.elts])
    if isinstance(node, ast.Dict):
        return _merge([_trace(item, environment) for item in node.values])
    if isinstance(node, ast.Call):
        call_name = _name(node.func)
        receiver = (
            _trace(node.func.value, environment) if isinstance(node.func, ast.Attribute) else None
        )
        value = _merge([receiver, *(_trace(item, environment) for item in node.args)])
        sanitizer = SANITIZERS.get(call_name) or SANITIZERS.get(call_name.rsplit(".", 1)[-1])
        if value is not None and sanitizer:
            return value.append(
                "sanitizer",
                sanitizer,
                node.lineno,
                f"{call_name} changes or validates the tainted value.",
            )
        if value is not None:
            label = (
                "String format"
                if call_name.endswith(".format")
                else f"Call {call_name or 'helper'}"
            )
            return value.append(
                "transformation",
                label,
                node.lineno,
                "Inter-procedural behavior is approximated; the callee is not executed.",
            )
    return None


def _remediation(category: VulnerabilityCategory) -> StaticRemediation:
    if category == VulnerabilityCategory.SQL_INJECTION:
        return StaticRemediation(
            summary="Keep user data separate from SQL syntax.",
            guidance=[
                "Use the database driver's parameter binding API.",
                "Allowlist identifiers that cannot be represented as bound values.",
            ],
            safe_example='cursor.execute("SELECT * FROM items WHERE id = ?", (item_id,))',
            verification=(
                "Repeat the code scan and confirm the request value no longer reaches SQL text."
            ),
        )
    if category == VulnerabilityCategory.SERVER_SIDE_TEMPLATE_INJECTION:
        return StaticRemediation(
            summary="Render a fixed template and pass user data as context.",
            guidance=[
                "Avoid compiling templates from request values.",
                "Keep autoescaping enabled.",
            ],
            safe_example='return render_template("result.html", value=user_value)',
            verification="Confirm the template name and source are constants during review.",
        )
    if category == VulnerabilityCategory.COMMAND_INJECTION:
        return StaticRemediation(
            summary="Do not concatenate request data into shell commands.",
            guidance=["Use a fixed executable and an argument list.", "Keep shell=False."],
            safe_example='subprocess.run(["ping", "-c", "1", validated_host], check=True)',
            verification="Confirm no tainted value controls a shell string or executable path.",
        )
    if category == VulnerabilityCategory.PATH_TRAVERSAL:
        return StaticRemediation(
            summary="Resolve paths under a fixed base and enforce containment.",
            guidance=[
                "Reject absolute paths and traversal segments.",
                "Use framework safe-file helpers.",
            ],
            safe_example=(
                "candidate = (BASE / name).resolve()\n"
                "if not candidate.is_relative_to(BASE): raise ValueError()"
            ),
            verification=(
                "Test that encoded and nested traversal names are rejected without reading files."
            ),
        )
    return StaticRemediation(
        summary="Encode untrusted data for its output context.",
        guidance=["Use an autoescaping template rather than a raw HTML response."],
        safe_example='return render_template("result.html", value=user_value)',
        verification="Confirm rendered request values are contextually encoded.",
    )


def _sink_details(call: ast.Call) -> tuple[VulnerabilityCategory, str, ast.AST] | None:
    call_name = _name(call.func)
    suffix = call_name.rsplit(".", 1)[-1]
    if suffix in {"execute", "executemany", "query", "raw"} and call.args:
        return VulnerabilityCategory.SQL_INJECTION, call_name, call.args[0]
    if suffix == "render_template_string" and call.args:
        return VulnerabilityCategory.SERVER_SIDE_TEMPLATE_INJECTION, call_name, call.args[0]
    if call_name == "os.system" and call.args:
        return VulnerabilityCategory.COMMAND_INJECTION, call_name, call.args[0]
    if call_name in {"subprocess.run", "subprocess.call", "subprocess.Popen"} and call.args:
        shell_enabled = any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in call.keywords
        )
        if shell_enabled:
            return VulnerabilityCategory.COMMAND_INJECTION, call_name, call.args[0]
    if suffix in {"open", "read_text", "write_text", "send_file"} and call.args:
        return VulnerabilityCategory.PATH_TRAVERSAL, call_name, call.args[0]
    if suffix in {"Response", "HTMLResponse", "make_response"} and call.args:
        return VulnerabilityCategory.XSS, call_name, call.args[0]
    return None


def _severity(category: VulnerabilityCategory) -> Severity:
    if category in {
        VulnerabilityCategory.SQL_INJECTION,
        VulnerabilityCategory.COMMAND_INJECTION,
        VulnerabilityCategory.SERVER_SIDE_TEMPLATE_INJECTION,
    }:
        return Severity.HIGH
    return Severity.MEDIUM


class _FunctionAnalyzer:
    def __init__(self, file_path: str, route: ExtractedRoute) -> None:
        self.file_path = file_path
        self.route = route
        self.environment: dict[str, _Taint] = {}
        self.findings: list[ExtractedStaticFinding] = []
        self.safe_decisions: list[str] = []
        for parameter in route.parameters:
            if parameter.location != "path":
                continue
            self.environment[parameter.name] = _Taint(
                (
                    StaticFlowStep(
                        id="step-0",
                        kind="source",
                        label=f"route parameter {parameter.name}",
                        line=route.line_start,
                        detail="Untrusted path input enters the route handler.",
                    ),
                ),
                parameter.name,
            )

    def analyze(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._statements(function.body)

    def _statements(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            self._scan_calls(statement)
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value_node = statement.value
                if value_node is None:
                    continue
                value = _trace(value_node, self.environment)
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                for target in targets:
                    for name in self._target_names(target):
                        if value is None:
                            self.environment.pop(name, None)
                        else:
                            self.environment[name] = value.append(
                                "transformation",
                                f"Assign {name}",
                                statement.lineno,
                                "The tainted value is stored in a local variable.",
                            )
            nested: list[list[ast.stmt]] = []
            if isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                nested = [statement.body, statement.orelse]
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                nested = [statement.body]
            elif isinstance(statement, ast.Try):
                nested = [statement.body, statement.orelse, statement.finalbody]
                nested.extend(handler.body for handler in statement.handlers)
            for body in nested:
                self._statements(body)

    @staticmethod
    def _target_names(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            return [name for item in node.elts for name in _FunctionAnalyzer._target_names(item)]
        return []

    def _scan_calls(self, statement: ast.stmt) -> None:
        for node in ast.walk(statement):
            if not isinstance(node, ast.Call):
                continue
            sink = _sink_details(node)
            if sink is None:
                continue
            category, sink_name, argument = sink
            value = _trace(argument, self.environment)
            if value is None:
                continue
            strong = STRONG_SANITIZERS.get(category, set())
            if value.sanitizers & strong:
                self.safe_decisions.append(
                    f"{self.file_path}:{node.lineno} {sink_name} received a strongly "
                    "sanitized value"
                )
                continue
            status = (
                StaticFindingStatus.MANUAL_CONFIRMATION_REQUIRED
                if value.sanitizers
                else StaticFindingStatus.STATIC_CANDIDATE
            )
            flow = value.append(
                "sink",
                sink_name,
                node.lineno,
                "Tainted data reaches a security-sensitive operation.",
            )
            limitations = [
                "Intra-procedural AST analysis does not prove runtime reachability.",
                "Dynamic dispatch, imported helpers, and framework middleware require review.",
            ]
            if flow.truncated:
                limitations.append(f"The displayed flow is capped at {MAX_FLOW_STEPS} steps.")
            self.findings.append(
                ExtractedStaticFinding(
                    file_path=self.file_path,
                    route_handler=self.route.handler_name,
                    category=category,
                    title=f"Potential {CATEGORY_NAMES[category]}",
                    status=status,
                    severity=_severity(category),
                    confidence=0.62 if value.sanitizers else 0.9,
                    source_label=value.steps[0].label,
                    sink_label=sink_name,
                    parameter=value.parameter,
                    source_line=value.steps[0].line,
                    sink_line=node.lineno,
                    sanitizers=sorted(value.sanitizers),
                    evidence=[
                        f"Source observed at line {value.steps[0].line}.",
                        f"Sensitive sink {sink_name} receives the traced value at line "
                        f"{node.lineno}.",
                    ],
                    flow_steps=list(flow.steps),
                    remediation=_remediation(category),
                    limitations=limitations,
                )
            )


def analyze_python_taint(
    content: str,
    file_path: str,
    routes: list[ExtractedRoute],
) -> tuple[list[ExtractedStaticFinding], list[str]]:
    """Trace request data inside extracted Python route handlers without execution."""

    tree = ast.parse(content, filename=file_path, mode="exec")
    by_handler = {route.handler_name: route for route in routes if route.file_path == file_path}
    findings: list[ExtractedStaticFinding] = []
    safe_decisions: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = by_handler.get(node.name)
        if route is None:
            continue
        analyzer = _FunctionAnalyzer(file_path, route)
        analyzer.analyze(node)
        findings.extend(analyzer.findings)
        safe_decisions.extend(analyzer.safe_decisions)
    unique: dict[tuple[str, int, str, str | None], ExtractedStaticFinding] = {}
    for finding in findings:
        key = (finding.category.value, finding.sink_line, finding.sink_label, finding.parameter)
        unique[key] = finding
    return list(unique.values())[:100], safe_decisions[:100]

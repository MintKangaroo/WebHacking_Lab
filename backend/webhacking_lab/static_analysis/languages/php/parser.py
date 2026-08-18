"""Conservative PHP lexical source-to-sink analysis without invoking PHP."""

import re
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

SUPERGLOBAL = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[\s*(['\"])(.*?)\2\s*\]",
    re.DOTALL,
)
VARIABLE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
ASSIGNMENT = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*(.+)", re.DOTALL)
SANITIZER_NAMES = {
    "intval": "integer conversion",
    "floatval": "numeric conversion",
    "htmlspecialchars": "HTML escaping",
    "htmlentities": "HTML escaping",
    "strip_tags": "HTML tag stripping",
    "basename": "basename normalization",
    "escapeshellarg": "shell argument escaping",
    "escapeshellcmd": "shell argument escaping",
    "mysqli_real_escape_string": "SQL string escaping",
    "addslashes": "SQL string escaping",
    "urlencode": "URL encoding",
    "rawurlencode": "URL encoding",
    "filter_var": "input filtering",
}
STRONG_SANITIZERS = {
    VulnerabilityCategory.SQL_INJECTION: {"integer conversion", "numeric conversion"},
    VulnerabilityCategory.XSS: {"HTML escaping"},
    VulnerabilityCategory.COMMAND_INJECTION: {"shell argument escaping"},
}
CATEGORY_NAMES = {
    VulnerabilityCategory.SQL_INJECTION: "SQL Injection",
    VulnerabilityCategory.XSS: "Cross-Site Scripting",
    VulnerabilityCategory.COMMAND_INJECTION: "Command Injection",
    VulnerabilityCategory.FILE_INCLUSION: "File Inclusion",
    VulnerabilityCategory.PATH_TRAVERSAL: "Path Traversal",
    VulnerabilityCategory.OPEN_REDIRECT: "Open Redirect",
}
MAX_FLOW_STEPS = 64


@dataclass(frozen=True)
class _PhpTaint:
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
    ) -> "_PhpTaint":
        sanitizers = self.sanitizers | ({label} if kind == "sanitizer" else set())
        if kind != "sink" and len(self.steps) >= MAX_FLOW_STEPS - 1:
            return _PhpTaint(self.steps, self.parameter, frozenset(sanitizers), True)
        steps = self.steps[: MAX_FLOW_STEPS - 1] if kind == "sink" else self.steps
        step = StaticFlowStep(
            id=f"step-{len(steps)}",
            kind=kind,
            label=label,
            line=line,
            detail=detail,
        )
        return _PhpTaint(
            (*steps, step),
            self.parameter,
            frozenset(sanitizers),
            self.truncated or len(self.steps) > len(steps),
        )


def _strip_comments(content: str) -> str:
    output: list[str] = []
    index = 0
    quote = ""
    line_comment = False
    block_comment = False
    while index < len(content):
        character = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
                output.append(character)
            else:
                output.append(" ")
        elif block_comment:
            if character == "*" and following == "/":
                output.extend((" ", " "))
                index += 1
                block_comment = False
            else:
                output.append("\n" if character == "\n" else " ")
        elif quote:
            output.append(character)
            if character == "\\" and following:
                output.append(following)
                index += 1
            elif character == quote:
                quote = ""
        elif character in {"'", '"'}:
            quote = character
            output.append(character)
        elif character == "/" and following in {"/", "*"}:
            output.extend((" ", " "))
            index += 1
            if following == "/":
                line_comment = True
            else:
                block_comment = True
        elif character == "#":
            output.append(" ")
            line_comment = True
        else:
            output.append(character)
        index += 1
    return "".join(output)


def _statements(content: str) -> list[tuple[str, int]]:
    cleaned = _strip_comments(content)
    cleaned = re.sub(
        r"<\?(?:php)?|\?>",
        lambda match: " " * len(match.group(0)),
        cleaned,
        flags=re.IGNORECASE,
    )
    values: list[tuple[str, int]] = []
    start = 0
    start_line = 1
    line = 1
    quote = ""
    escaped = False
    for index, character in enumerate(cleaned):
        if character == "\n":
            line += 1
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == ";":
            raw_statement = cleaned[start:index]
            statement = raw_statement.strip()
            if statement:
                leading = raw_statement[: len(raw_statement) - len(raw_statement.lstrip())]
                values.append((statement, start_line + leading.count("\n")))
            start = index + 1
            start_line = line
    raw_trailing = cleaned[start:]
    trailing = raw_trailing.strip()
    if trailing:
        leading = raw_trailing[: len(raw_trailing) - len(raw_trailing.lstrip())]
        values.append((trailing, start_line + leading.count("\n")))
    return values


def _source(expression: str, line: int) -> _PhpTaint | None:
    match = SUPERGLOBAL.search(expression)
    if match is None:
        return None
    location = match.group(1).lower()
    parameter = match.group(3)
    label = f"$_{match.group(1)}[{parameter!r}]"
    return _PhpTaint(
        (
            StaticFlowStep(
                id="step-0",
                kind="source",
                label=label,
                line=line,
                detail=f"Untrusted PHP {location} input enters the endpoint.",
            ),
        ),
        parameter,
    )


def _outer_call_name(expression: str) -> str | None:
    stripped = expression.strip()
    match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", stripped)
    if match is None:
        return None
    depth = 0
    quote = ""
    escaped = False
    for index in range(match.end() - 1, len(stripped)):
        character = stripped[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return match.group(1).lower() if not stripped[index + 1 :].strip() else None
    return None


def _trace(expression: str, line: int, environment: dict[str, _PhpTaint]) -> _PhpTaint | None:
    values = [value for value in [_source(expression, line)] if value is not None]
    seen_variables: set[str] = set()
    for variable in VARIABLE.findall(expression):
        if variable in seen_variables:
            continue
        seen_variables.add(variable)
        if variable in environment:
            values.append(environment[variable])
    if not values:
        return None
    value = values[0]
    sanitizers = set(value.sanitizers)
    for traced in values[1:]:
        sanitizers.intersection_update(traced.sanitizers)
    value = _PhpTaint(
        value.steps,
        value.parameter,
        frozenset(sanitizers),
        any(traced.truncated for traced in values),
    )
    sanitizer_name = _outer_call_name(expression)
    sanitizer_label = SANITIZER_NAMES.get(sanitizer_name or "")
    if sanitizer_name is not None and sanitizer_label is not None:
        value = value.append(
            "sanitizer",
            sanitizer_label,
            line,
            f"{sanitizer_name} changes or validates the tainted value.",
        )
    if "." in expression or ('"' in expression and VARIABLE.search(expression)):
        value = value.append(
            "transformation",
            "PHP string composition",
            line,
            "Tainted data is concatenated or interpolated into a string.",
        )
    return value


def _split_arguments(value: str) -> list[str]:
    arguments: list[str] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for index, character in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {"'", '"'}:
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}" and depth:
            depth -= 1
        elif character == "," and depth == 0:
            arguments.append(value[start:index].strip())
            start = index + 1
    arguments.append(value[start:].strip())
    return arguments


def _call_body(statement: str, marker: str) -> str | None:
    # Match a bare function call, not a method (``->exec``) or a longer
    # identifier (``pcntl_exec``, ``$exec``).
    pattern = r"(?<![\w$>-])" + re.escape(marker) + r"\s*\((.*)\)"
    match = re.search(pattern, statement, re.IGNORECASE | re.DOTALL)
    return match.group(1) if match is not None else None


def _sink(statement: str) -> tuple[VulnerabilityCategory, str, str] | None:
    mysqli = _call_body(statement, "mysqli_query")
    if mysqli is not None:
        arguments = _split_arguments(mysqli)
        if len(arguments) >= 2:
            return VulnerabilityCategory.SQL_INJECTION, "mysqli_query", arguments[1]
    mysql = _call_body(statement, "mysql_query")
    if mysql is not None:
        return VulnerabilityCategory.SQL_INJECTION, "mysql_query", _split_arguments(mysql)[0]
    postgres = _call_body(statement, "pg_query")
    if postgres is not None:
        arguments = _split_arguments(postgres)
        return VulnerabilityCategory.SQL_INJECTION, "pg_query", arguments[-1]
    method_sql = re.search(r"->\s*(query|exec)\s*\((.*)\)", statement, re.IGNORECASE | re.DOTALL)
    if method_sql is not None:
        sink_name = f"PDO::{method_sql.group(1)}"
        return VulnerabilityCategory.SQL_INJECTION, sink_name, method_sql.group(2)
    header = _call_body(statement, "header")
    if header is not None and re.search(r"location\s*:", header, re.IGNORECASE):
        return VulnerabilityCategory.OPEN_REDIRECT, "header", header
    for name in ("shell_exec", "passthru", "system", "exec", "popen", "proc_open", "eval"):
        body = _call_body(statement, name)
        if body is not None:
            return VulnerabilityCategory.COMMAND_INJECTION, name, _split_arguments(body)[0]
    for name in ("fopen", "readfile", "file_get_contents", "file_put_contents", "unlink"):
        body = _call_body(statement, name)
        if body is not None:
            return VulnerabilityCategory.PATH_TRAVERSAL, name, _split_arguments(body)[0]
    inclusion = re.search(
        r"\b(include|include_once|require|require_once)\s*(?:\((.*)\)|(.*))",
        statement,
        re.IGNORECASE | re.DOTALL,
    )
    if inclusion is not None:
        expression = inclusion.group(2) or inclusion.group(3) or ""
        return VulnerabilityCategory.FILE_INCLUSION, inclusion.group(1), expression
    response = re.search(r"\b(echo|print)\s+(.+)", statement, re.IGNORECASE | re.DOTALL)
    if response is not None:
        return VulnerabilityCategory.XSS, response.group(1), response.group(2)
    return None


def _remediation(category: VulnerabilityCategory) -> StaticRemediation:
    if category == VulnerabilityCategory.SQL_INJECTION:
        return StaticRemediation(
            summary="Use a prepared statement and bind data separately.",
            guidance=["Prepare constant SQL.", "Bind values with execute parameters."],
            safe_example=(
                '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$id]);'
            ),
            verification="Confirm no superglobal-derived value is concatenated into SQL text.",
        )
    if category == VulnerabilityCategory.COMMAND_INJECTION:
        return StaticRemediation(
            summary="Avoid operating-system commands for request-controlled behavior.",
            guidance=["Use a native library.", "If unavoidable, enforce a strict allowlist."],
            safe_example=(
                "if (!in_array($host, $allowedHosts, true)) { "
                "throw new InvalidArgumentException(); }"
            ),
            verification=(
                "Confirm request data cannot alter command syntax or executable selection."
            ),
        )
    if category == VulnerabilityCategory.FILE_INCLUSION:
        return StaticRemediation(
            summary="Map a small allowlist key to fixed include files.",
            guidance=["Never pass a request value directly to include or require."],
            safe_example=(
                '$pages = ["help" => __DIR__ . "/pages/help.php"];\ninclude $pages[$page];'
            ),
            verification="Confirm unknown page keys are rejected before file resolution.",
        )
    if category == VulnerabilityCategory.PATH_TRAVERSAL:
        return StaticRemediation(
            summary="Resolve file paths under a fixed base and enforce containment.",
            guidance=[
                "Reject absolute paths and '..' segments before opening files.",
                "Compare realpath() against the intended base directory.",
            ],
            safe_example=(
                "$base = realpath(__DIR__ . '/uploads');\n"
                "$target = realpath($base . '/' . $name);\n"
                "if ($target === false || strpos($target, $base) !== 0) { exit; }"
            ),
            verification="Confirm encoded and nested traversal names cannot escape the base dir.",
        )
    if category == VulnerabilityCategory.OPEN_REDIRECT:
        return StaticRemediation(
            summary="Redirect only to vetted, application-controlled destinations.",
            guidance=[
                "Allowlist redirect targets or restrict them to relative paths.",
                "Reject absolute URLs and protocol-relative ('//host') values.",
            ],
            safe_example=(
                "$target = $_GET['next'] ?? '/';\n"
                "if ($target === '' || $target[0] !== '/' || substr($target, 0, 2) === '//') "
                "{ $target = '/'; }\nheader('Location: ' . $target);"
            ),
            verification="Confirm external hosts and scheme-relative URLs cannot set the target.",
        )
    return StaticRemediation(
        summary="Encode untrusted text for the HTML output context.",
        guidance=["Use htmlspecialchars with ENT_QUOTES and an explicit charset."],
        safe_example='echo htmlspecialchars($value, ENT_QUOTES, "UTF-8");',
        verification="Confirm special characters are encoded before HTML output.",
    )


def analyze_php_taint(
    content: str,
    file_path: str,
    routes: list[ExtractedRoute],
) -> tuple[list[ExtractedStaticFinding], list[str]]:
    """Trace common PHP superglobals through assignments into security-sensitive sinks."""

    environment: dict[str, _PhpTaint] = {}
    findings: list[ExtractedStaticFinding] = []
    safe_decisions: list[str] = []
    route = next((value for value in routes if value.file_path == file_path), None)
    handler = route.handler_name if route is not None else None
    if "->prepare(" in content and "->execute(" in content:
        safe_decisions.append(f"{file_path}: prepared statement pattern observed")
    for statement, line in _statements(content):
        assignment = ASSIGNMENT.search(statement)
        if assignment is not None:
            variable = f"${assignment.group(1)}"
            value = _trace(assignment.group(2), line, environment)
            if value is None:
                environment.pop(variable, None)
            else:
                environment[variable] = value.append(
                    "transformation",
                    f"Assign {variable}",
                    line,
                    "The tainted value is stored in a PHP variable.",
                )
        sink = _sink(statement)
        if sink is None:
            continue
        category, sink_name, expression = sink
        value = _trace(expression, line, environment)
        if value is None:
            continue
        if value.sanitizers & STRONG_SANITIZERS.get(category, set()):
            safe_decisions.append(f"{file_path}:{line} {sink_name} received a sanitized value")
            continue
        status = (
            StaticFindingStatus.MANUAL_CONFIRMATION_REQUIRED
            if value.sanitizers
            else StaticFindingStatus.STATIC_CANDIDATE
        )
        flow = value.append(
            "sink",
            sink_name,
            line,
            "Tainted data reaches a security-sensitive PHP operation.",
        )
        limitations = [
            "Lexical PHP analysis does not resolve includes, aliases, or dynamic dispatch.",
            "Runtime reachability and framework middleware require manual confirmation.",
        ]
        if flow.truncated:
            limitations.append(f"The displayed flow is capped at {MAX_FLOW_STEPS} steps.")
        findings.append(
            ExtractedStaticFinding(
                file_path=file_path,
                route_handler=handler,
                category=category,
                title=f"Potential {CATEGORY_NAMES[category]}",
                status=status,
                severity=(
                    Severity.MEDIUM
                    if category
                    in {VulnerabilityCategory.XSS, VulnerabilityCategory.OPEN_REDIRECT}
                    else Severity.HIGH
                ),
                confidence=0.6 if value.sanitizers else 0.88,
                source_label=value.steps[0].label,
                sink_label=sink_name,
                parameter=value.parameter,
                source_line=value.steps[0].line,
                sink_line=line,
                sanitizers=sorted(value.sanitizers),
                evidence=[
                    f"Superglobal source observed at line {value.steps[0].line}.",
                    f"Sensitive sink {sink_name} receives the traced value at line {line}.",
                ],
                flow_steps=list(flow.steps),
                remediation=_remediation(category),
                limitations=limitations,
            )
        )
    unique: dict[tuple[str, int, str, str | None], ExtractedStaticFinding] = {}
    for finding in findings:
        key = (finding.category.value, finding.sink_line, finding.sink_label, finding.parameter)
        unique[key] = finding
    return list(unique.values())[:100], safe_decisions[:100]

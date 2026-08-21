"""Conservative JavaScript/Express lexical source-to-sink analysis.

No JavaScript is executed. The analyzer strips comments, splits statements on
``;``/newlines at the top level and inside ``{}`` blocks (so handler-callback
bodies are recovered, while strings, template literals, and ``()``/``[]`` call
arguments stay opaque), and traces Express request inputs through simple
assignments into security-sensitive sinks.
"""

import re
from dataclasses import dataclass
from typing import Literal

from webhacking_lab.domain.enums import (
    Severity,
    StaticFindingStatus,
    VulnerabilityCategory,
)
from webhacking_lab.static_analysis.models import (
    AuthenticationInfo,
    ExtractedRoute,
    ExtractedStaticFinding,
    StaticFlowStep,
    StaticParameter,
    StaticRemediation,
)

# ``req.query.id``, ``req.body['name']``, ``req.params.file`` and friends.
REQUEST_SOURCE = re.compile(
    r"\b(?:req|request)\s*\.\s*(query|body|params|cookies|signedCookies|headers)"
    r"(?:\s*\.\s*([A-Za-z_$][\w$]*)|\s*\[\s*(['\"])(.*?)\3\s*\])?",
)
# ``req.get('x-header')`` / ``req.header('x')`` header accessors.
REQUEST_GETTER = re.compile(
    r"\b(?:req|request)\s*\.\s*(?:get|header)\s*\(\s*(['\"])(.*?)\1\s*\)",
)
IDENTIFIER = re.compile(r"(?<![.\w$])([A-Za-z_$][\w$]*)")
ASSIGNMENT = re.compile(
    r"^(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=(?![=>])\s*(.+)$",
    re.DOTALL,
)
SANITIZER_NAMES = {
    "parseint": "integer conversion",
    "parsefloat": "numeric conversion",
    "number": "numeric conversion",
    "encodeuricomponent": "URL encoding",
    "encodeuri": "URL encoding",
    "escape": "HTML escaping",
    "escapehtml": "HTML escaping",
    "encode": "HTML escaping",
    "basename": "basename normalization",
}
STRONG_SANITIZERS = {
    VulnerabilityCategory.SQL_INJECTION: {"integer conversion", "numeric conversion"},
    VulnerabilityCategory.XSS: {"HTML escaping"},
    VulnerabilityCategory.OPEN_REDIRECT: {"URL encoding"},
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
_QUOTES = {"'", '"', "`"}

EXPRESS_ROUTE = re.compile(
    r"\b(app|router|[A-Za-z_$][\w$]*[Rr]outer)\s*\.\s*"
    r"(get|post|put|patch|delete|all)\s*\(\s*(['\"`])(.*?)\3",
)
_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
_AUTH_TOKENS = (
    "authenticate",
    "isauthenticated",
    "requireauth",
    "requirelogin",
    "ensureauth",
    "ensureloggedin",
    "passport",
    "authmiddleware",
    "checkauth",
)
_ROUTE_PARAM = re.compile(r":([A-Za-z_$][\w$]*)")


@dataclass(frozen=True)
class _JsTaint:
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
    ) -> "_JsTaint":
        sanitizers = self.sanitizers | ({label} if kind == "sanitizer" else set())
        if kind != "sink" and len(self.steps) >= MAX_FLOW_STEPS - 1:
            return _JsTaint(self.steps, self.parameter, frozenset(sanitizers), True)
        steps = self.steps[: MAX_FLOW_STEPS - 1] if kind == "sink" else self.steps
        step = StaticFlowStep(
            id=f"step-{len(steps)}",
            kind=kind,
            label=label,
            line=line,
            detail=detail,
        )
        return _JsTaint(
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
        elif character in _QUOTES:
            quote = character
            output.append(character)
        elif character == "/" and following in {"/", "*"}:
            output.extend((" ", " "))
            index += 1
            line_comment = following == "/"
            block_comment = following == "*"
        else:
            output.append(character)
        index += 1
    return "".join(output)


def _statements(content: str) -> list[tuple[str, int]]:
    """Split into (statement, line) pairs on ``;`` and newlines.

    A bracket stack allows splitting at the top level and inside ``{}`` block
    bodies (function/handler bodies), but not inside ``()`` call arguments or
    ``[]`` arrays, so a callback body's statements are recovered even when the
    handler is registered inside ``app.get(...)``.
    """

    cleaned = _strip_comments(content)
    values: list[tuple[str, int]] = []
    start = 0
    start_line = 1
    line = 1
    quote = ""
    escaped = False
    stack: list[str] = []

    def can_split() -> bool:
        return not stack or stack[-1] == "{"

    def flush(end: int) -> None:
        nonlocal start, start_line
        raw = cleaned[start:end]
        statement = raw.strip()
        if statement:
            leading = raw[: len(raw) - len(raw.lstrip())]
            values.append((statement, start_line + leading.count("\n")))
        start = end + 1
        start_line = line

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
        if character in _QUOTES:
            quote = character
        elif character == "{":
            flush(index)  # end the pre-block prefix; start the body fresh
            stack.append(character)
        elif character in "([":
            stack.append(character)
        elif character == "}":
            flush(index)  # emit the final in-block statement
            if stack:
                stack.pop()
        elif character in ")]":
            if stack:
                stack.pop()
        elif character in {";", "\n"} and can_split():
            flush(index)
    raw_trailing = cleaned[start:]
    trailing = raw_trailing.strip()
    if trailing:
        leading = raw_trailing[: len(raw_trailing) - len(raw_trailing.lstrip())]
        values.append((trailing, start_line + leading.count("\n")))
    return values


def _source(expression: str, line: int) -> _JsTaint | None:
    getter = REQUEST_GETTER.search(expression)
    if getter is not None:
        parameter = getter.group(2)
        return _JsTaint(
            (
                StaticFlowStep(
                    id="step-0",
                    kind="source",
                    label=f"req.get({parameter!r})",
                    line=line,
                    detail="An untrusted request header enters the endpoint.",
                ),
            ),
            parameter,
        )
    match = REQUEST_SOURCE.search(expression)
    if match is None:
        return None
    location = match.group(1)
    parameter = match.group(2) or match.group(4)
    suffix = f".{parameter}" if match.group(2) else (f"[{parameter!r}]" if parameter else "")
    return _JsTaint(
        (
            StaticFlowStep(
                id="step-0",
                kind="source",
                label=f"req.{location}{suffix}",
                line=line,
                detail=f"Untrusted Express request {location} input enters the endpoint.",
            ),
        ),
        parameter,
    )


def _balanced(text: str, open_index: int) -> tuple[str, int] | None:
    """Return the argument text inside the parenthesis opened at ``open_index``."""

    depth = 0
    quote = ""
    escaped = False
    for index in range(open_index, len(text)):
        character = text[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in _QUOTES:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index], index
    return None


def _outer_call_name(expression: str) -> str | None:
    stripped = expression.strip()
    match = re.match(
        r"(?:[A-Za-z_$][\w$]*\s*\.\s*)*([A-Za-z_$][\w$]*)\s*\(",
        stripped,
    )
    if match is None:
        return None
    body = _balanced(stripped, match.end() - 1)
    if body is None or stripped[body[1] + 1 :].strip():
        return None
    return match.group(1).lower()


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
        if character in _QUOTES:
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


def _trace(expression: str, line: int, environment: dict[str, _JsTaint]) -> _JsTaint | None:
    values = [value for value in [_source(expression, line)] if value is not None]
    seen: set[str] = set()
    for identifier in IDENTIFIER.findall(expression):
        if identifier in seen:
            continue
        seen.add(identifier)
        if identifier in environment:
            values.append(environment[identifier])
    if not values:
        return None
    value = values[0]
    sanitizers = set(value.sanitizers)
    for traced in values[1:]:
        sanitizers.intersection_update(traced.sanitizers)
    value = _JsTaint(
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
    if "+" in expression or "`" in expression or ".concat(" in expression:
        value = value.append(
            "transformation",
            "JS string composition",
            line,
            "Tainted data is concatenated or interpolated into a string.",
        )
    return value


def _method_call(statement: str, methods: tuple[str, ...]) -> tuple[str, str] | None:
    pattern = r"\.\s*(" + "|".join(methods) + r")\s*\("
    for match in re.finditer(pattern, statement):
        body = _balanced(statement, match.end() - 1)
        if body is not None:
            return match.group(1), body[0]
    return None


def _bare_call(statement: str, names: tuple[str, ...]) -> tuple[str, str] | None:
    pattern = r"(?<![.\w$])(" + "|".join(names) + r")\s*\("
    for match in re.finditer(pattern, statement):
        body = _balanced(statement, match.end() - 1)
        if body is not None:
            return match.group(1), body[0]
    return None


def _sink(statement: str) -> tuple[VulnerabilityCategory, str, str] | None:
    sql = _method_call(statement, ("query", "execute"))
    if sql is not None:
        return VulnerabilityCategory.SQL_INJECTION, sql[0], _split_arguments(sql[1])[0]
    redirect = _method_call(statement, ("redirect",))
    if redirect is not None:
        target = _split_arguments(redirect[1])[-1]
        return VulnerabilityCategory.OPEN_REDIRECT, "res.redirect", target
    file_sink = _method_call(
        statement,
        (
            "sendFile",
            "download",
            "readFile",
            "readFileSync",
            "createReadStream",
            "writeFile",
            "writeFileSync",
            "unlink",
        ),
    )
    if file_sink is not None:
        prefix = "res" if file_sink[0] in {"sendFile", "download"} else "fs"
        arg = _split_arguments(file_sink[1])[0]
        return VulnerabilityCategory.PATH_TRAVERSAL, f"{prefix}.{file_sink[0]}", arg
    response = _method_call(statement, ("send", "write", "end"))
    if response is not None:
        arg = _split_arguments(response[1])[0]
        return VulnerabilityCategory.XSS, f"res.{response[0]}", arg
    command = _method_call(statement, ("exec", "execSync")) or _bare_call(
        statement, ("exec", "execSync", "eval")
    )
    if command is not None:
        arg = _split_arguments(command[1])[0]
        return VulnerabilityCategory.COMMAND_INJECTION, command[0], arg
    inclusion = _bare_call(statement, ("require",))
    if inclusion is not None:
        return VulnerabilityCategory.FILE_INCLUSION, "require", _split_arguments(inclusion[1])[0]
    return None


def _remediation(category: VulnerabilityCategory) -> StaticRemediation:
    if category == VulnerabilityCategory.SQL_INJECTION:
        return StaticRemediation(
            summary="Use parameterized queries and bind values separately.",
            guidance=["Keep SQL text constant.", "Pass request data as query parameters."],
            safe_example='db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);',
            verification="Confirm no request value is concatenated or interpolated into SQL text.",
        )
    if category == VulnerabilityCategory.COMMAND_INJECTION:
        return StaticRemediation(
            summary="Avoid the shell for request-controlled behavior.",
            guidance=[
                "Use execFile/spawn with an argument array and no shell.",
                "If a command is unavoidable, enforce a strict allowlist.",
            ],
            safe_example='execFile("ping", ["-c", "1", host], (err, out) => {});',
            verification="Confirm request data cannot alter command syntax or the executable.",
        )
    if category == VulnerabilityCategory.PATH_TRAVERSAL:
        return StaticRemediation(
            summary="Resolve paths under a fixed base and enforce containment.",
            guidance=[
                "Reject absolute paths and '..' segments.",
                "Compare path.resolve(base, name) against the intended base directory.",
            ],
            safe_example=(
                "const target = path.resolve(base, req.query.file);\n"
                "if (!target.startsWith(base + path.sep)) return res.sendStatus(400);"
            ),
            verification="Confirm encoded and nested traversal names cannot escape the base dir.",
        )
    if category == VulnerabilityCategory.FILE_INCLUSION:
        return StaticRemediation(
            summary="Never require() a request-controlled path.",
            guidance=["Map a small allowlist key to fixed module paths."],
            safe_example=(
                'const mods = { help: "./help" };\nconst mod = require(mods[req.query.page]);'
            ),
            verification="Confirm unknown keys are rejected before module resolution.",
        )
    if category == VulnerabilityCategory.OPEN_REDIRECT:
        return StaticRemediation(
            summary="Redirect only to vetted, application-controlled destinations.",
            guidance=[
                "Allowlist redirect targets or restrict them to relative paths.",
                "Reject absolute and protocol-relative ('//host') URLs.",
            ],
            safe_example=(
                'let next = req.query.next || "/";\n'
                'if (next[0] !== "/" || next.startsWith("//")) next = "/";\n'
                "res.redirect(next);"
            ),
            verification="Confirm external hosts and scheme-relative URLs cannot set the target.",
        )
    return StaticRemediation(
        summary="Encode untrusted text for the HTML output context.",
        guidance=[
            "Return JSON, or render through an auto-escaping template.",
            "If building HTML, escape with a library before sending.",
        ],
        safe_example="res.send(escapeHtml(req.query.q));",
        verification="Confirm special characters are encoded before HTML output.",
    )


def extract_express_routes(content: str, file_path: str) -> list[ExtractedRoute]:
    """Recover Express ``app``/``router`` route registrations without executing JS."""

    cleaned = _strip_comments(content)
    routes: list[ExtractedRoute] = []
    for match in EXPRESS_ROUTE.finditer(cleaned):
        obj = match.group(1)
        verb = match.group(2)
        route_path = match.group(4)
        line = cleaned.count("\n", 0, match.start()) + 1
        methods = list(_HTTP_METHODS) if verb == "all" else [verb.upper()]
        parameters = [
            StaticParameter(name=name, location="path", required=True)
            for name in dict.fromkeys(_ROUTE_PARAM.findall(route_path))
        ]
        # Inspect the whole registration argument list for an auth middleware.
        paren = cleaned.find("(", match.start(), match.end())
        body = _balanced(cleaned, paren) if paren != -1 else None
        tail = (body[0] if body is not None else "").lower()
        authenticated = any(token in tail for token in _AUTH_TOKENS)
        authentication = AuthenticationInfo(
            required=authenticated,
            mechanisms=["route middleware"] if authenticated else [],
            limitations=[
                "Express middleware order and global guards require manual confirmation.",
            ],
        )
        routes.append(
            ExtractedRoute(
                file_path=file_path,
                framework="Express",
                methods=methods,
                path=route_path,
                handler_name=f"{obj}.{verb}",
                line_start=line,
                line_end=line,
                parameters=parameters,
                authentication=authentication,
            )
        )
    return routes


def analyze_javascript_taint(
    content: str,
    file_path: str,
    routes: list[ExtractedRoute],
) -> tuple[list[ExtractedStaticFinding], list[str]]:
    """Trace Express request inputs through assignments into sensitive sinks."""

    environment: dict[str, _JsTaint] = {}
    findings: list[ExtractedStaticFinding] = []
    safe_decisions: list[str] = []
    route = next((value for value in routes if value.file_path == file_path), None)
    handler = route.handler_name if route is not None else None
    for statement, line in _statements(content):
        assignment = ASSIGNMENT.match(statement)
        if assignment is not None and _sink(statement) is None:
            variable = assignment.group(1)
            value = _trace(assignment.group(2), line, environment)
            if value is None:
                environment.pop(variable, None)
            else:
                environment[variable] = value.append(
                    "transformation",
                    f"Assign {variable}",
                    line,
                    "The tainted value is stored in a variable.",
                )
            continue
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
            "Tainted data reaches a security-sensitive operation.",
        )
        limitations = [
            "Lexical JS analysis does not resolve imports, aliases, or dynamic dispatch.",
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
                    if category in {VulnerabilityCategory.XSS, VulnerabilityCategory.OPEN_REDIRECT}
                    else Severity.HIGH
                ),
                confidence=0.6 if value.sanitizers else 0.85,
                source_label=value.steps[0].label,
                sink_label=sink_name,
                parameter=value.parameter,
                source_line=value.steps[0].line,
                sink_line=line,
                sanitizers=sorted(value.sanitizers),
                evidence=[
                    f"Express request source observed at line {value.steps[0].line}.",
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

"""Extract Flask/FastAPI-style routes using Python's inert AST parser."""

import ast
import re

from webhacking_lab.static_analysis.models import (
    AuthenticationInfo,
    ExtractedRoute,
    StaticParameter,
)

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
FLASK_PATH_PARAMETER = re.compile(r"<(?:(?:[^:>]+):)?([^>]+)>")
FASTAPI_PATH_PARAMETER = re.compile(r"{([^}:]+)(?::[^}]+)?}")
AUTH_MARKERS = {
    "login_required",
    "jwt_required",
    "auth_required",
    "requires_auth",
    "permission_required",
}


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    if isinstance(node, ast.Attribute):
        prefix = _decorator_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _literal_string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_methods(call: ast.Call, route_name: str) -> list[str]:
    suffix = route_name.rsplit(".", maxsplit=1)[-1].lower()
    if suffix in HTTP_METHODS:
        return [suffix.upper()]
    for keyword in call.keywords:
        if keyword.arg != "methods" or not isinstance(keyword.value, (ast.List, ast.Tuple)):
            continue
        methods = [
            value.upper()
            for item in keyword.value.elts
            if (value := _literal_string(item)) is not None
        ]
        if methods:
            return sorted(set(methods))
    return ["GET"]


def _framework(route_name: str, frameworks: set[str]) -> str:
    suffix = route_name.rsplit(".", maxsplit=1)[-1].lower()
    if "FastAPI" in frameworks or suffix == "api_route":
        return "FastAPI"
    if "Bottle" in frameworks:
        return "Bottle"
    return "Flask"


def _path_parameters(path: str) -> list[StaticParameter]:
    names = FLASK_PATH_PARAMETER.findall(path) + FASTAPI_PATH_PARAMETER.findall(path)
    return [
        StaticParameter(name=name, location="path", required=True) for name in dict.fromkeys(names)
    ]


def _constant_key(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _request_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[StaticParameter]:
    parameters: dict[tuple[str, str], StaticParameter] = {}
    locations = {
        "args": "query",
        "form": "form",
        "values": "request",
        "headers": "header",
        "cookies": "cookie",
        "files": "multipart",
    }
    for node in ast.walk(function):
        container: ast.expr | None = None
        key: str | None = None
        if isinstance(node, ast.Subscript):
            container = node.value
            key = _constant_key(node.slice)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
        ):
            container = node.func.value
            key = _constant_key(node.args[0])
        if not isinstance(container, ast.Attribute) or key is None:
            continue
        if not isinstance(container.value, ast.Name) or container.value.id != "request":
            continue
        location = locations.get(container.attr)
        if location:
            parameters[(key, location)] = StaticParameter(name=key, location=location)
    return list(parameters.values())


def _auth_info(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    route_decorator: ast.expr,
) -> AuthenticationInfo:
    mechanisms: set[str] = set()
    for decorator in function.decorator_list:
        if decorator is route_decorator:
            continue
        name = _decorator_name(decorator)
        if any(marker in name.lower() for marker in AUTH_MARKERS):
            mechanisms.add(name)
    for default in [*function.args.defaults, *function.args.kw_defaults]:
        if isinstance(default, ast.Call) and _decorator_name(default.func).endswith("Depends"):
            mechanisms.add("Depends")
    return AuthenticationInfo(
        required=bool(mechanisms),
        mechanisms=sorted(mechanisms),
        limitations=["Middleware and blueprint-level authentication may not be visible here."],
    )


def extract_python_routes(
    content: str,
    file_path: str,
    frameworks: set[str],
) -> list[ExtractedRoute]:
    """Parse decorators without importing, compiling, or evaluating uploaded code."""

    tree = ast.parse(content, filename=file_path, mode="exec")
    routes: list[ExtractedRoute] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            name = _decorator_name(decorator.func)
            suffix = name.rsplit(".", maxsplit=1)[-1].lower()
            if suffix not in HTTP_METHODS | {"route", "api_route"}:
                continue
            path = _literal_string(decorator.args[0])
            if path is None or not path.startswith("/"):
                continue
            parameters = _path_parameters(path)
            known = {(item.name, item.location) for item in parameters}
            parameters.extend(
                item
                for item in _request_parameters(node)
                if (item.name, item.location) not in known
            )
            routes.append(
                ExtractedRoute(
                    file_path=file_path,
                    framework=_framework(name, frameworks),
                    methods=_literal_methods(decorator, name),
                    path=path,
                    handler_name=node.name,
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    parameters=parameters,
                    authentication=_auth_info(node, decorator),
                )
            )
    return routes

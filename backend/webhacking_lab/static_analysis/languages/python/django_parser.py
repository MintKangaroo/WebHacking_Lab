"""Extract Django URL patterns and view handlers using the inert AST parser.

Django splits routing across files: ``urls.py`` maps a path to a view callable,
while the view function lives in ``views.py`` with the convention
``def view(request, ...)``. Route paths are recovered from ``urls.py`` when
available and matched to view definitions by name; views are still surfaced when
no matching pattern is found so taint analysis has an entry point.
"""

import ast
import re

from webhacking_lab.static_analysis.models import (
    AuthenticationInfo,
    ExtractedRoute,
    StaticParameter,
)

URL_CALLS = {"path", "re_path", "url"}
DJANGO_PATH_PARAMETER = re.compile(r"<(?:[^:>]+:)?([^>]+)>")
DJANGO_REGEX_PARAMETER = re.compile(r"\(\?P<([^>]+)>")
AUTH_MARKERS = {
    "login_required",
    "permission_required",
    "user_passes_test",
    "staff_member_required",
}


def _literal_string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _view_name(node: ast.expr) -> str | None:
    """Return the referenced view's function/class name, if resolvable."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    # Class-based views are registered as ``MyView.as_view()``.
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "as_view":
            return _view_name(node.func.value)
        return _view_name(node.func)
    return None


def _path_parameters(route_path: str) -> list[str]:
    names = DJANGO_PATH_PARAMETER.findall(route_path) + DJANGO_REGEX_PARAMETER.findall(route_path)
    return list(dict.fromkeys(names))


def extract_django_urlpatterns(content: str, file_path: str) -> dict[str, tuple[str, list[str]]]:
    """Map view names to their route path and path parameter names from urls.py."""

    try:
        tree = ast.parse(content, filename=file_path, mode="exec")
    except (SyntaxError, ValueError):
        return {}
    mapping: dict[str, tuple[str, list[str]]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in URL_CALLS or len(node.args) < 2:
            continue
        route_path = _literal_string(node.args[0])
        view_name = _view_name(node.args[1])
        if route_path is None or view_name is None:
            continue
        normalized = route_path if route_path.startswith("/") else f"/{route_path}"
        mapping.setdefault(view_name, (normalized, _path_parameters(route_path)))
    return mapping


def _auth_info(function: ast.FunctionDef | ast.AsyncFunctionDef) -> AuthenticationInfo:
    mechanisms = {
        name
        for decorator in function.decorator_list
        if any(marker in (name := _view_name(decorator) or "").lower() for marker in AUTH_MARKERS)
    }
    return AuthenticationInfo(
        required=bool(mechanisms),
        mechanisms=sorted(mechanisms),
        limitations=["Middleware and class-based mixin authentication may not be visible here."],
    )


def _is_view(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    positional = [*function.args.posonlyargs, *function.args.args]
    return bool(positional) and positional[0].arg == "request"


def extract_django_routes(
    content: str,
    file_path: str,
    url_map: dict[str, tuple[str, list[str]]],
) -> list[ExtractedRoute]:
    """Surface Django view functions (``def view(request, ...)``) as routes."""

    try:
        tree = ast.parse(content, filename=file_path, mode="exec")
    except (SyntaxError, ValueError):
        return []
    routes: list[ExtractedRoute] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not _is_view(node):
            continue
        mapped = url_map.get(node.name)
        if mapped is not None:
            route_path, param_names = mapped
        else:
            route_path, param_names = f"/{node.name}/", []
        parameters = [
            StaticParameter(name=name, location="path", required=True) for name in param_names
        ]
        routes.append(
            ExtractedRoute(
                file_path=file_path,
                framework="Django",
                methods=["GET", "POST"],
                path=route_path,
                handler_name=node.name,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                parameters=parameters,
                authentication=_auth_info(node),
            )
        )
    return routes

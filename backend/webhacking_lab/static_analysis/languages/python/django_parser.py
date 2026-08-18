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
HTTP_VERB_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
DJANGO_PATH_PARAMETER = re.compile(r"<(?:[^:>]+:)?([^>]+)>")
DJANGO_REGEX_PARAMETER = re.compile(r"\(\?P<([^>]+)>")
AUTH_MARKERS = {
    "login_required",
    "permission_required",
    "user_passes_test",
    "staff_member_required",
    "loginrequiredmixin",
    "permissionrequiredmixin",
    "userpassestestmixin",
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


def _auth_info(nodes: list[ast.expr]) -> AuthenticationInfo:
    mechanisms = {
        name
        for node in nodes
        if any(marker in (name := _view_name(node) or "").lower() for marker in AUTH_MARKERS)
    }
    return AuthenticationInfo(
        required=bool(mechanisms),
        mechanisms=sorted(mechanisms),
        limitations=["Middleware and class-based mixin authentication may not be visible here."],
    )


def _positional_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [argument.arg for argument in (*function.args.posonlyargs, *function.args.args)]


def _is_function_view(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    positional = _positional_names(function)
    return bool(positional) and positional[0] == "request"


def _is_view_method(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return function.name in HTTP_VERB_METHODS and "request" in _positional_names(function)[:2]


def _signature_url_params(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[str]:
    return [name for name in _positional_names(function) if name not in {"self", "request"}]


def _build_route(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    file_path: str,
    handler_name: str,
    methods: list[str],
    mapped: tuple[str, list[str]] | None,
    default_path: str,
    auth_nodes: list[ast.expr],
) -> ExtractedRoute:
    if mapped is not None:
        route_path, param_names = mapped
    else:
        route_path, param_names = default_path, _signature_url_params(function)
    parameters = [
        StaticParameter(name=name, location="path", required=True) for name in param_names
    ]
    return ExtractedRoute(
        file_path=file_path,
        framework="Django",
        methods=methods,
        path=route_path,
        handler_name=handler_name,
        line_start=function.lineno,
        line_end=function.end_lineno or function.lineno,
        parameters=parameters,
        authentication=_auth_info(auth_nodes),
    )


def extract_django_routes(
    content: str,
    file_path: str,
    url_map: dict[str, tuple[str, list[str]]],
) -> list[ExtractedRoute]:
    """Surface Django function views and class-based view handlers as routes."""

    try:
        tree = ast.parse(content, filename=file_path, mode="exec")
    except (SyntaxError, ValueError):
        return []
    routes: list[ExtractedRoute] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_function_view(node):
            routes.append(
                _build_route(
                    node,
                    file_path=file_path,
                    handler_name=node.name,
                    methods=["GET", "POST"],
                    mapped=url_map.get(node.name),
                    default_path=f"/{node.name}/",
                    auth_nodes=node.decorator_list,
                )
            )
        elif isinstance(node, ast.ClassDef):
            mapped = url_map.get(node.name)
            for member in node.body:
                if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not _is_view_method(member):
                    continue
                routes.append(
                    _build_route(
                        member,
                        file_path=file_path,
                        handler_name=f"{node.name}.{member.name}",
                        methods=[member.name.upper()],
                        mapped=mapped,
                        default_path=f"/{node.name}/",
                        auth_nodes=[*node.decorator_list, *node.bases, *member.decorator_list],
                    )
                )
    return routes

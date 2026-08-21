"""Language-routed, non-executing endpoint inventory extraction."""

from pathlib import Path

from webhacking_lab.static_analysis.languages.javascript.parser import extract_express_routes
from webhacking_lab.static_analysis.languages.python.ast_parser import extract_python_routes
from webhacking_lab.static_analysis.languages.python.django_parser import (
    extract_django_routes,
    extract_django_urlpatterns,
)
from webhacking_lab.static_analysis.models import (
    AuthenticationInfo,
    ExtractedRoute,
    IndexedFile,
    RouteExtraction,
)

MAX_AST_FILE_BYTES = 1_000_000


def _php_route(relative_path: str) -> ExtractedRoute:
    path = Path(relative_path)
    if path.name.lower() == "index.php":
        parent = path.parent.as_posix()
        route_path = "/" if parent == "." else f"/{parent.strip('/')}/"
    else:
        route_path = f"/{path.as_posix()}"
    return ExtractedRoute(
        file_path=relative_path,
        framework="Plain PHP",
        methods=["GET", "POST"],
        path=route_path,
        handler_name=path.name,
        line_start=1,
        line_end=1,
        parameters=[],
        authentication=AuthenticationInfo(
            limitations=["PHP authentication and router configuration require Phase 11 analysis."]
        ),
    )


def extract_routes(
    root: Path,
    files: list[IndexedFile],
    frameworks: list[str],
) -> RouteExtraction:
    """Extract Python AST routes and conservative Plain PHP file endpoints."""

    routes: list[ExtractedRoute] = []
    warnings: list[str] = []
    framework_set = set(frameworks)
    django = "Django" in framework_set
    express = "Express" in framework_set
    python_files = [
        entry
        for entry in files
        if entry.language == "python" and entry.size_bytes <= MAX_AST_FILE_BYTES
    ]
    url_map: dict[str, tuple[str, list[str]]] = {}
    if django:
        # First pass: recover route paths from urls.py before matching views.
        for entry in python_files:
            content = (root / entry.relative_path).read_text(encoding="utf-8", errors="replace")
            url_map.update(extract_django_urlpatterns(content, entry.relative_path))
    for entry in files:
        path = root / entry.relative_path
        if entry.language == "python":
            if entry.size_bytes > MAX_AST_FILE_BYTES:
                warnings.append(f"Skipped oversized Python AST input: {entry.relative_path}")
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            try:
                routes.extend(extract_python_routes(content, entry.relative_path, framework_set))
            except (SyntaxError, ValueError, TypeError) as error:
                warnings.append(
                    f"Skipped malformed Python AST: {entry.relative_path} ({type(error).__name__})"
                )
            if django:
                routes.extend(extract_django_routes(content, entry.relative_path, url_map))
        elif entry.language == "javascript" and express:
            if entry.size_bytes > MAX_AST_FILE_BYTES:
                warnings.append(f"Skipped oversized JavaScript input: {entry.relative_path}")
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            routes.extend(extract_express_routes(content, entry.relative_path))
        elif entry.language == "php":
            routes.append(_php_route(entry.relative_path))
    routes.sort(key=lambda item: (item.file_path, item.line_start, item.path))
    return RouteExtraction(routes=routes, warnings=warnings)

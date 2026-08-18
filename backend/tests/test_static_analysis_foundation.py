"""Unit tests for archive guards, project detection, AST routes, and redaction."""

import io
import json
import stat
import zipfile
from pathlib import Path

import pytest
from fastapi import UploadFile
from sqlalchemy import create_engine, inspect

from webhacking_lab.database.session import _bridge_legacy_code_project_authorization
from webhacking_lab.domain.exceptions import UploadLimitError, UploadValidationError
from webhacking_lab.static_analysis.archive import SecureUploadStore
from webhacking_lab.static_analysis.file_index import index_source_tree, language_for
from webhacking_lab.static_analysis.languages.python.ast_parser import extract_python_routes
from webhacking_lab.static_analysis.models import IndexedFile, UploadPolicy
from webhacking_lab.static_analysis.project_detector import detect_project
from webhacking_lab.static_analysis.route_extractor import extract_routes
from webhacking_lab.static_analysis.secret_scanner import find_secrets, redact_source


def _upload(name: str, content: bytes) -> UploadFile:
    return UploadFile(filename=name, file=io.BytesIO(content))


def _archive(entries: dict[str, bytes], executable: str | None = None) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, content in entries.items():
            if name == executable:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                bundle.writestr(info, content)
            else:
                bundle.writestr(name, content)
    return output.getvalue()


def test_legacy_code_project_schema_bridge_is_idempotent() -> None:
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE code_projects (id VARCHAR(36) NOT NULL PRIMARY KEY, name TEXT NOT NULL)"
        )
        connection.exec_driver_sql(
            "INSERT INTO code_projects (id, name) VALUES ('legacy', 'Preserved source')"
        )
        _bridge_legacy_code_project_authorization(connection)
        _bridge_legacy_code_project_authorization(connection)
        columns = {value["name"] for value in inspect(connection).get_columns("code_projects")}
        row = connection.exec_driver_sql(
            "SELECT name, authorization_confirmed, authorization_notes FROM code_projects"
        ).one()

    assert {"authorization_confirmed", "authorization_notes"}.issubset(columns)
    assert tuple(row) == ("Preserved source", 0, "")


@pytest.mark.asyncio
async def test_secure_store_accepts_plain_files_and_resolves_exact_key(tmp_path: Path) -> None:
    policy = UploadPolicy(
        max_archive_bytes=10_000,
        max_extracted_bytes=10_000,
        max_files=3,
        max_single_file_bytes=5_000,
    )
    store = SecureUploadStore(tmp_path / "artifacts", policy)
    root = await store.ingest(
        [_upload("src/app.py", b"print('ok')"), _upload("requirements.txt", b"Flask")],
        "00000000-0000-0000-0000-000000000001",
    )
    assert (root / "src/app.py").read_text() == "print('ok')"
    assert store.resolve("00000000-0000-0000-0000-000000000001") == root
    store.delete("00000000-0000-0000-0000-000000000001")
    assert not root.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "content", "exception"),
    [
        ("../escape.py", b"pass", UploadValidationError),
        ("nested\\escape.py", b"pass", UploadValidationError),
        ("binary.py", b"a\x00b", UploadValidationError),
        ("large.py", b"A" * 11, UploadLimitError),
    ],
)
async def test_secure_store_rejects_unsafe_plain_file(
    tmp_path: Path,
    name: str,
    content: bytes,
    exception: type[Exception],
) -> None:
    store = SecureUploadStore(
        tmp_path / name.replace("/", "_"),
        UploadPolicy(
            max_archive_bytes=100,
            max_extracted_bytes=20,
            max_files=2,
            max_single_file_bytes=10,
        ),
    )
    with pytest.raises(exception):
        await store.ingest([_upload(name, content)], "safe-key")


@pytest.mark.asyncio
async def test_secure_store_rejects_nested_bad_signature_and_executable_zip(
    tmp_path: Path,
) -> None:
    policy = UploadPolicy(
        max_archive_bytes=10_000,
        max_extracted_bytes=10_000,
        max_files=10,
        max_single_file_bytes=5_000,
    )
    for index, content in enumerate(
        (
            b"not-a-zip",
            _archive({"nested.zip": b"PK\x05\x06"}),
            _archive({"run.py": b"pass"}, executable="run.py"),
        )
    ):
        store = SecureUploadStore(tmp_path / str(index), policy)
        with pytest.raises(UploadValidationError):
            await store.ingest([_upload("source.zip", content)], f"key-{index}")


@pytest.mark.asyncio
async def test_secure_store_rejects_empty_mixed_zip_and_file_count(tmp_path: Path) -> None:
    policy = UploadPolicy(
        max_archive_bytes=10_000,
        max_extracted_bytes=10_000,
        max_files=1,
        max_single_file_bytes=5_000,
    )
    for index, uploads, exception in (
        (0, [], UploadValidationError),
        (
            1,
            [_upload("source.zip", _archive({"app.py": b"pass"})), _upload("x.py", b"pass")],
            UploadValidationError,
        ),
        (2, [_upload("a.py", b"pass"), _upload("b.py", b"pass")], UploadLimitError),
    ):
        store = SecureUploadStore(tmp_path / f"reject-{index}", policy)
        with pytest.raises(exception):
            await store.ingest(uploads, f"key-{index}")


def test_file_index_secret_redaction_and_project_detection(tmp_path: Path) -> None:
    files = {
        "app.py": "from fastapi import FastAPI\nTOKEN='abcdefghijk'\n",
        "pyproject.toml": "[project]\ndependencies=['fastapi']\n",
        "package.json": json.dumps({"dependencies": {"express": "5", "next": "15"}}),
        "composer.json": json.dumps({"require": {"laravel/framework": "^12"}}),
        "pom.xml": "<dependency>org.springframework.boot spring-boot</dependency>",
        "ignored.png": "image-like-text",
    }
    for name, content in files.items():
        path = tmp_path / name
        path.write_text(content)
    policy = UploadPolicy(
        max_archive_bytes=100_000,
        max_extracted_bytes=100_000,
        max_files=20,
        max_single_file_bytes=20_000,
    )
    indexed, warnings = index_source_tree(tmp_path, policy)
    detection = detect_project(tmp_path, indexed)
    assert language_for(Path("Dockerfile")) == "dockerfile"
    assert language_for(Path("unknown.asset")) is None
    assert any("ignored.png" in value for value in warnings)
    assert detection.frameworks == ["Express", "FastAPI", "Laravel", "Next.js", "Spring Boot"]
    app = next(value for value in indexed if value.relative_path == "app.py")
    assert app.secret_findings[0].kind == "assigned_secret"
    rendered, changed = redact_source(files["app.py"])
    assert changed is True and "abcdefghijk" not in rendered


def test_secret_scanner_masks_complete_private_key_and_jwt() -> None:
    source = (
        "-----BEGIN PRIVATE KEY-----\nsecret-lines\n-----END PRIVATE KEY-----\n"
        "token = eyJabcdefgh.abcdefghijk.abcdefghijk\n"
    )
    findings = find_secrets(source)
    rendered, changed = redact_source(source)
    assert {"private_key", "jwt"}.issubset({value.kind for value in findings})
    assert changed is True
    assert "secret-lines" not in rendered
    assert "eyJabcdefgh" not in rendered


def test_python_ast_routes_cover_flask_fastapi_parameters_and_malformed() -> None:
    source = """
@app.post("/login")
async def login(username: str = Depends(user)):
    token = request.headers["X-Token"]
    return token

@app.api_route("/items/{item_id}", methods=["GET", "PATCH"])
def item(item_id):
    return request.cookies.get("session")
"""
    routes = extract_python_routes(source, "api.py", {"FastAPI"})
    assert [value.methods for value in routes] == [["POST"], ["GET", "PATCH"]]
    assert routes[0].authentication.required is True
    assert routes[0].parameters[0].location == "header"
    assert {value.location for value in routes[1].parameters} == {"path", "cookie"}
    with pytest.raises(SyntaxError):
        extract_python_routes("def broken(:", "broken.py", {"Flask"})


def test_route_extractor_records_malformed_python_and_non_index_php(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def broken(:")
    (tmp_path / "login.php").write_text("<?php echo 'login';")
    entries, _ = index_source_tree(
        tmp_path,
        UploadPolicy(
            max_archive_bytes=1_000,
            max_extracted_bytes=1_000,
            max_files=5,
            max_single_file_bytes=500,
        ),
    )
    extraction = extract_routes(tmp_path, entries, ["Plain PHP"])
    assert extraction.routes[0].path == "/login.php"
    assert "malformed Python AST" in extraction.warnings[0]
    oversized = extract_routes(
        tmp_path,
        [
            IndexedFile(
                relative_path="broken.py",
                language="python",
                size_bytes=1_000_001,
                sha256="a" * 64,
                secret_findings=[],
                warning_codes=[],
            )
        ],
        ["Flask"],
    )
    assert "oversized Python AST" in oversized.warnings[0]


def test_route_extractor_matches_django_views_to_urlpatterns(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        "from django.urls import path\n"
        "from . import views\n"
        "urlpatterns = [\n"
        "    path('items/<int:item_id>/', views.item_detail),\n"
        "]\n"
    )
    (tmp_path / "views.py").write_text(
        "def item_detail(request, item_id):\n"
        "    return item_id\n\n"
        "def _helper(value):\n"  # first parameter is not `request`
        "    return value\n"
    )
    entries, _ = index_source_tree(
        tmp_path,
        UploadPolicy(
            max_archive_bytes=2_000,
            max_extracted_bytes=2_000,
            max_files=5,
            max_single_file_bytes=1_000,
        ),
    )
    routes = extract_routes(tmp_path, entries, ["Django"]).routes
    django_routes = [route for route in routes if route.framework == "Django"]
    assert [route.handler_name for route in django_routes] == ["item_detail"]
    detail = django_routes[0]
    assert detail.path == "/items/<int:item_id>/"
    assert [parameter.name for parameter in detail.parameters] == ["item_id"]


def test_route_extractor_maps_django_class_based_view_methods(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        "from django.urls import path\n"
        "from .views import ItemView\n"
        "urlpatterns = [path('items/<int:item_id>/', ItemView.as_view())]\n"
    )
    (tmp_path / "views.py").write_text(
        "from django.views import View\n\n"
        "class ItemView(View):\n"
        "    def get(self, request, item_id):\n"
        "        return item_id\n"
        "    def post(self, request):\n"
        "        return request\n"
        "    def helper(self, value):\n"  # not an HTTP verb
        "        return value\n"
    )
    entries, _ = index_source_tree(
        tmp_path,
        UploadPolicy(
            max_archive_bytes=2_000,
            max_extracted_bytes=2_000,
            max_files=5,
            max_single_file_bytes=1_000,
        ),
    )
    routes = extract_routes(tmp_path, entries, ["Django"]).routes
    handlers = {route.handler_name: route for route in routes if route.framework == "Django"}
    assert set(handlers) == {"ItemView.get", "ItemView.post"}
    assert handlers["ItemView.get"].methods == ["GET"]
    assert handlers["ItemView.get"].path == "/items/<int:item_id>/"
    assert [p.name for p in handlers["ItemView.get"].parameters] == ["item_id"]


def test_route_extractor_skips_django_views_when_framework_absent(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text("def index(request):\n    return request\n")
    entries, _ = index_source_tree(
        tmp_path,
        UploadPolicy(
            max_archive_bytes=1_000,
            max_extracted_bytes=1_000,
            max_files=5,
            max_single_file_bytes=500,
        ),
    )
    routes = extract_routes(tmp_path, entries, ["Flask"]).routes
    assert all(route.framework != "Django" for route in routes)


def test_project_detector_reports_malformed_manifests_and_plain_php(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[broken")
    (tmp_path / "package.json").write_text("{")
    (tmp_path / "composer.json").write_text("{")
    (tmp_path / "index.php").write_text("<?php echo 'ok';")
    entries, _ = index_source_tree(
        tmp_path,
        UploadPolicy(
            max_archive_bytes=10_000,
            max_extracted_bytes=10_000,
            max_files=10,
            max_single_file_bytes=2_000,
        ),
    )
    detection = detect_project(tmp_path, entries)
    assert detection.frameworks == ["Plain PHP"]
    assert detection.warnings == [
        "composer.json could not be parsed",
        "package.json could not be parsed",
        "pyproject.toml could not be parsed; source imports were still checked",
    ]


def test_index_rejects_symlink_hardlink_and_limits(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    source.write_text("pass")
    link = tmp_path / "link.py"
    link.symlink_to(source)
    policy = UploadPolicy(
        max_archive_bytes=100,
        max_extracted_bytes=100,
        max_files=10,
        max_single_file_bytes=100,
    )
    with pytest.raises(UploadValidationError):
        index_source_tree(tmp_path, policy)
    link.unlink()
    hard = tmp_path / "hard.py"
    hard.hardlink_to(source)
    with pytest.raises(UploadValidationError):
        index_source_tree(tmp_path, policy)
    hard.unlink()
    with pytest.raises(UploadLimitError):
        index_source_tree(
            tmp_path,
            policy.model_copy(update={"max_files": 0}),
        )


def test_index_marks_encoding_and_sensitive_filename_and_rejects_binary(tmp_path: Path) -> None:
    (tmp_path / ".env").write_bytes(b"TOKEN=abcdefghijk\n")
    (tmp_path / "bad.py").write_bytes(b"name = '\xff'\n")
    policy = UploadPolicy(
        max_archive_bytes=1_000,
        max_extracted_bytes=1_000,
        max_files=5,
        max_single_file_bytes=500,
    )
    entries, _ = index_source_tree(tmp_path, policy)
    by_path = {value.relative_path: value for value in entries}
    assert by_path[".env"].warning_codes == ["sensitive_file_name"]
    assert by_path["bad.py"].warning_codes == ["encoding_replacement"]
    (tmp_path / "binary.py").write_bytes(b"a\x00b")
    with pytest.raises(UploadValidationError):
        index_source_tree(tmp_path, policy)

"""Index regular text files without importing or executing uploaded code."""

import hashlib
import os
from pathlib import Path

from webhacking_lab.domain.exceptions import UploadLimitError, UploadValidationError
from webhacking_lab.static_analysis.models import IndexedFile, UploadPolicy
from webhacking_lab.static_analysis.secret_scanner import find_secrets

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".php": "php",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".json": "json",
    ".toml": "toml",
    ".xml": "xml",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "scss",
    ".sql": "sql",
    ".gradle": "groovy",
    ".kts": "kotlin",
    ".md": "markdown",
    ".txt": "text",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "text",
    ".env": "dotenv",
    ".properties": "properties",
}
KNOWN_TEXT_NAMES = {
    "Dockerfile": "dockerfile",
    "Makefile": "makefile",
    "Procfile": "text",
    ".env": "dotenv",
    ".env.example": "dotenv",
    "requirements.txt": "text",
}
IGNORED_PARTS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
}


def language_for(path: Path) -> str | None:
    """Return a presentation language for recognized source/configuration files."""

    if path.name in KNOWN_TEXT_NAMES:
        return KNOWN_TEXT_NAMES[path.name]
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def index_source_tree(root: Path, policy: UploadPolicy) -> tuple[list[IndexedFile], list[str]]:
    """Hash and inspect bounded regular files while rejecting filesystem links."""

    entries: list[IndexedFile] = []
    warnings: list[str] = []
    seen_files = 0
    seen_bytes = 0
    for directory, directories, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        directories[:] = sorted(item for item in directories if item not in IGNORED_PARTS)
        if directory_path.is_symlink():
            raise UploadValidationError("Symbolic links are not accepted in source projects")
        for filename in sorted(filenames):
            path = directory_path / filename
            if any(part in IGNORED_PARTS for part in path.relative_to(root).parts):
                continue
            stat_result = path.lstat()
            if path.is_symlink() or not path.is_file():
                raise UploadValidationError("Only regular source files are accepted")
            if stat_result.st_nlink != 1:
                raise UploadValidationError("Hard-linked source files are not accepted")
            seen_files += 1
            seen_bytes += stat_result.st_size
            if seen_files > policy.max_files:
                raise UploadLimitError("Source project exceeds the configured file count")
            if stat_result.st_size > policy.max_single_file_bytes:
                raise UploadLimitError("A source file exceeds the configured per-file limit")
            if seen_bytes > policy.max_extracted_bytes:
                raise UploadLimitError("Source project exceeds the extracted-size limit")
            language = language_for(path)
            if language is None:
                warnings.append(
                    f"Skipped unsupported file type: {path.relative_to(root).as_posix()}"
                )
                continue
            raw = path.read_bytes()
            if b"\x00" in raw:
                raise UploadValidationError("Binary content is not accepted as source text")
            content = raw.decode("utf-8", errors="replace")
            warning_codes: list[str] = []
            if "\ufffd" in content:
                warning_codes.append("encoding_replacement")
            if path.name == ".env" or path.suffix.lower() in {".pem", ".key"}:
                warning_codes.append("sensitive_file_name")
            entries.append(
                IndexedFile(
                    relative_path=path.relative_to(root).as_posix(),
                    language=language,
                    size_bytes=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest(),
                    secret_findings=find_secrets(content),
                    warning_codes=warning_codes,
                )
            )
    return entries, sorted(set(warnings))

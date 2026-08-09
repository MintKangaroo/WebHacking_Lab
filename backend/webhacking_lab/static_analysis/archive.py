"""Securely stage source files and ZIP archives as inert artifacts."""

import os
import shutil
import stat
import tempfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath

from fastapi import UploadFile

from webhacking_lab.domain.exceptions import UploadLimitError, UploadValidationError
from webhacking_lab.static_analysis.models import UploadPolicy

EXECUTABLE_SUFFIXES = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".com",
    ".msi",
    ".apk",
    ".appimage",
}
ARCHIVE_SUFFIXES = {".zip", ".jar", ".war", ".ear", ".7z", ".rar", ".tgz", ".gz"}
CHUNK_SIZE = 64 * 1024
ZIP_MIME_TYPES = {"application/zip", "application/x-zip-compressed", "application/octet-stream"}
BINARY_MIME_PREFIXES = ("image/", "audio/", "video/", "font/")
BINARY_MIME_TYPES = {
    "application/pdf",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-sharedlib",
}


def _relative_name(raw_name: str) -> PurePosixPath:
    normalized = unicodedata.normalize("NFC", raw_name)
    if not normalized or len(normalized) > 1_024 or "\\" in normalized or "\x00" in normalized:
        raise UploadValidationError("Upload paths must be normalized relative POSIX paths")
    path = PurePosixPath(normalized)
    if (
        not path.parts
        or path.is_absolute()
        or path.parts[0].endswith(":")
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise UploadValidationError("Upload paths cannot be absolute or contain traversal")
    return path


def _ensure_non_executable(path: PurePosixPath, mode: int = 0) -> None:
    if path.suffix.lower() in EXECUTABLE_SUFFIXES:
        raise UploadValidationError("Executable files are not accepted")
    if mode and mode & 0o111:
        raise UploadValidationError("Files with executable mode bits are not accepted")


def _validate_declared_mime(upload: UploadFile, *, archive: bool) -> None:
    """Reject a declared binary type that conflicts with inert source or ZIP handling."""

    mime = (upload.content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if not mime:
        return
    if archive and mime not in ZIP_MIME_TYPES:
        raise UploadValidationError("The declared MIME type does not match a ZIP archive")
    if not archive and (mime.startswith(BINARY_MIME_PREFIXES) or mime in BINARY_MIME_TYPES):
        raise UploadValidationError("The declared MIME type is not source text")


class SecureUploadStore:
    """Own staging, validation, atomic placement, and cleanup for source artifacts."""

    def __init__(self, root: Path, policy: UploadPolicy) -> None:
        self._root = root.expanduser().resolve()
        self._policy = policy

    async def ingest(self, files: list[UploadFile], storage_key: str) -> Path:
        """Validate and atomically place one ZIP or a bounded set of source files."""

        if not files:
            raise UploadValidationError("At least one source file is required")
        self._root.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".source-staging-", dir=self._root))
        final = self._root / storage_key
        try:
            if len(files) == 1 and Path(files[0].filename or "").suffix.lower() == ".zip":
                _validate_declared_mime(files[0], archive=True)
                await self._ingest_zip(files[0], staging)
            else:
                if any(Path(item.filename or "").suffix.lower() == ".zip" for item in files):
                    raise UploadValidationError("A ZIP archive must be uploaded by itself")
                await self._ingest_files(files, staging)
            if final.exists():
                raise UploadValidationError("The source artifact key is already in use")
            os.replace(staging, final)
            return final
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        finally:
            for upload in files:
                await upload.close()

    async def _ingest_files(self, files: list[UploadFile], staging: Path) -> None:
        if len(files) > self._policy.max_files:
            raise UploadLimitError("Upload exceeds the configured file count")
        total = 0
        names: set[str] = set()
        for upload in files:
            relative = _relative_name(upload.filename or "")
            _ensure_non_executable(relative)
            _validate_declared_mime(upload, archive=False)
            rendered = relative.as_posix()
            if rendered in names:
                raise UploadValidationError("Duplicate normalized upload paths are not accepted")
            names.add(rendered)
            destination = staging.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with destination.open("xb") as handle:
                while chunk := await upload.read(CHUNK_SIZE):
                    written += len(chunk)
                    total += len(chunk)
                    if written > self._policy.max_single_file_bytes:
                        raise UploadLimitError("A source file exceeds the configured limit")
                    if total > self._policy.max_extracted_bytes:
                        raise UploadLimitError("Upload exceeds the extracted-size limit")
                    handle.write(chunk)
            self._reject_binary_header(destination)

    async def _ingest_zip(self, upload: UploadFile, staging: Path) -> None:
        archive = staging.parent / f"{staging.name}.zip"
        size = 0
        try:
            with archive.open("xb") as handle:
                while chunk := await upload.read(CHUNK_SIZE):
                    size += len(chunk)
                    if size > self._policy.max_archive_bytes:
                        raise UploadLimitError("ZIP archive exceeds the configured upload limit")
                    handle.write(chunk)
            with archive.open("rb") as handle:
                signature = handle.read(4)
            if signature not in {b"PK\x03\x04", b"PK\x05\x06"}:
                raise UploadValidationError("The uploaded .zip file has an invalid signature")
            self._extract_zip(archive, staging)
        except zipfile.BadZipFile as error:
            raise UploadValidationError("The ZIP archive is malformed") from error
        finally:
            archive.unlink(missing_ok=True)

    def _extract_zip(self, archive: Path, staging: Path) -> None:
        total = 0
        file_count = 0
        names: set[str] = set()
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                relative = _relative_name(info.filename)
                rendered = relative.as_posix()
                if rendered in names:
                    raise UploadValidationError("Duplicate normalized ZIP paths are not accepted")
                names.add(rendered)
                if info.flag_bits & 0x1:
                    raise UploadValidationError("Encrypted ZIP entries are not accepted")
                mode = info.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type == stat.S_IFLNK:
                    raise UploadValidationError("Symbolic links are not accepted in ZIP archives")
                if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise UploadValidationError("Only regular files are accepted in ZIP archives")
                if info.is_dir():
                    continue
                _ensure_non_executable(relative, mode)
                if relative.suffix.lower() in ARCHIVE_SUFFIXES:
                    raise UploadValidationError("Nested archives are not accepted")
                file_count += 1
                if file_count > self._policy.max_files:
                    raise UploadLimitError("ZIP archive exceeds the configured file count")
                if info.file_size > self._policy.max_single_file_bytes:
                    raise UploadLimitError("A ZIP entry exceeds the configured per-file limit")
                total += info.file_size
                if total > self._policy.max_extracted_bytes:
                    raise UploadLimitError("ZIP archive exceeds the extracted-size limit")
                destination = staging.joinpath(*relative.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with bundle.open(info) as source, destination.open("xb") as target:
                    while chunk := source.read(CHUNK_SIZE):
                        written += len(chunk)
                        if written > self._policy.max_single_file_bytes or written > info.file_size:
                            raise UploadLimitError("A ZIP entry expanded beyond its declared limit")
                        target.write(chunk)
                self._reject_binary_header(destination)

    @staticmethod
    def _reject_binary_header(path: Path) -> None:
        header = path.read_bytes()[:4096]
        if header.startswith((b"\x7fELF", b"MZ")) or b"\x00" in header:
            raise UploadValidationError("Binary or executable content is not accepted")

    def delete(self, storage_key: str) -> None:
        """Remove exactly one validated artifact directory after a failed transaction."""

        target = (self._root / storage_key).resolve()
        if target.parent != self._root or not target.name:
            raise UploadValidationError("Invalid artifact cleanup target")
        shutil.rmtree(target, ignore_errors=True)

    def resolve(self, storage_key: str) -> Path:
        """Resolve one database-owned UUID key without accepting a user path."""

        target = (self._root / storage_key).resolve()
        if target.parent != self._root or not target.is_dir():
            raise UploadValidationError("Source artifact storage is unavailable")
        return target

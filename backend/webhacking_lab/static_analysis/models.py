"""Typed contracts for untrusted source upload and route inventory."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from webhacking_lab.domain.enums import CodeProjectStatus


class StaticAnalysisModel(BaseModel):
    """Strict base model for the source-analysis boundary."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)


class UploadPolicy(StaticAnalysisModel):
    """Hard limits applied before untrusted project files become visible."""

    max_archive_bytes: int = 50_000_000
    max_extracted_bytes: int = 200_000_000
    max_files: int = 5_000
    max_single_file_bytes: int = 5_000_000
    max_archive_depth: int = 2


class CodeProjectCreate(StaticAnalysisModel):
    """Create an empty source-analysis container under an existing project."""

    project_id: UUID
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=2_000)
    authorization_confirmed: Literal[True]
    authorization_notes: str = Field(min_length=10, max_length=2_000)
    confirmation_phrase: Literal["UPLOAD INERT SOURCE"]


class CodeProjectRead(StaticAnalysisModel):
    """Safe source project summary without a host filesystem path."""

    id: UUID
    project_id: UUID
    name: str
    description: str
    authorization_confirmed: bool
    authorization_notes: str
    status: CodeProjectStatus
    languages: list[str]
    frameworks: list[str]
    dependency_files: list[str]
    warnings: list[str]
    total_files: int
    total_bytes: int
    secret_findings_count: int
    analyzed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class CodeFileRead(StaticAnalysisModel):
    """Indexed file metadata; content is retrieved through a separate redacted endpoint."""

    id: UUID
    relative_path: str
    language: str
    size_bytes: int
    sha256: str
    secret_findings_count: int
    warning_codes: list[str]
    route_count: int


class CodeFileContentRead(CodeFileRead):
    """Size-bounded source text with recognized secrets masked."""

    content: str
    redacted: bool
    truncated: bool


class StaticParameter(StaticAnalysisModel):
    """Input inferred from a route path, handler, or framework request accessor."""

    name: str
    location: str
    required: bool = False


class AuthenticationInfo(StaticAnalysisModel):
    """Conservative authentication annotation extracted without executing middleware."""

    required: bool = False
    mechanisms: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class StaticRoute(StaticAnalysisModel):
    """Route inventory item linked to a source file and line range."""

    id: UUID
    code_file_id: UUID
    framework: str
    methods: list[str]
    path: str
    handler_name: str
    file_path: str
    line_start: int
    line_end: int
    parameters: list[StaticParameter]
    authentication: AuthenticationInfo
    findings: list[str]


class CodeUploadRead(StaticAnalysisModel):
    """Upload acceptance result after indexing; no uploaded code has been run."""

    project: CodeProjectRead
    files: list[CodeFileRead]
    policy: UploadPolicy
    execution_performed: bool = False


class CodeAnalysisRead(StaticAnalysisModel):
    """Route inventory analysis summary."""

    project: CodeProjectRead
    routes: list[StaticRoute]
    analysis_log: list[str]
    limitations: list[str]


class SecretFinding(StaticAnalysisModel):
    """Secret-shaped value location without retaining the value itself."""

    kind: str
    line: int


class IndexedFile(StaticAnalysisModel):
    """Internal immutable file index entry."""

    relative_path: str
    language: str
    size_bytes: int
    sha256: str
    secret_findings: list[SecretFinding]
    warning_codes: list[str]


class ProjectDetection(StaticAnalysisModel):
    """Languages, frameworks, and manifests detected without dependency installation."""

    languages: list[str]
    frameworks: list[str]
    dependency_files: list[str]
    warnings: list[str]


class ExtractedRoute(StaticAnalysisModel):
    """Internal route before database identifiers are assigned."""

    file_path: str
    framework: str
    methods: list[str]
    path: str
    handler_name: str
    line_start: int
    line_end: int
    parameters: list[StaticParameter]
    authentication: AuthenticationInfo
    findings: list[str] = Field(default_factory=list)


class RouteExtraction(StaticAnalysisModel):
    """Routes plus parser limitations safe to display in the analysis log."""

    routes: list[ExtractedRoute]
    warnings: list[str]


JsonObject = dict[str, Any]

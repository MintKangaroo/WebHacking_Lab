"""Stable domain enumerations persisted as strings."""

from enum import StrEnum


class WorkspaceMode(StrEnum):
    """Authorization context for a project or workspace."""

    CTF = "ctf"
    AUTHORIZED_PENTEST = "authorized_pentest"
    LOCAL_LAB = "local_lab"


class AnalysisMode(StrEnum):
    """Analysis input mode selected by a workspace."""

    MANUAL_HTTP = "manual_http"
    URL_SCAN = "url_scan"
    SOURCE_CODE = "source_code"
    HYBRID = "hybrid"


class AuditEventType(StrEnum):
    """Auditable state changes available in Phase 2."""

    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_DELETED = "project.deleted"
    WORKSPACE_CREATED = "workspace.created"
    WORKSPACE_UPDATED = "workspace.updated"
    SCOPE_RULE_CREATED = "scope_rule.created"
    SCOPE_CHECKED = "scope.checked"
    REQUEST_IMPORTED = "request.imported"
    REQUEST_CREATED = "request.created"
    REQUEST_CLONED = "request.cloned"

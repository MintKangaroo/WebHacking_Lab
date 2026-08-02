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
    """Auditable state changes."""

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
    WORKSPACE_EXECUTION_ENABLED = "workspace.execution_enabled"
    WORKSPACE_EXECUTION_DISABLED = "workspace.execution_disabled"
    REQUEST_EXECUTION_PREVIEWED = "request.execution_previewed"
    REQUEST_EXECUTION_STARTED = "request.execution_started"
    REQUEST_EXECUTION_COMPLETED = "request.execution_completed"
    REQUEST_EXECUTION_BLOCKED = "request.execution_blocked"
    ANALYSIS_STARTED = "analysis.started"
    ANALYSIS_COMPLETED = "analysis.completed"


class VulnerabilityCategory(StrEnum):
    """Initial passive analysis categories."""

    SECURITY_HEADERS = "security_headers"
    CORS = "cors"
    JWT = "jwt"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    AUTHENTICATION = "authentication"


class Severity(StrEnum):
    """Finding impact estimate independent from confidence."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationStatus(StrEnum):
    """Evidence maturity without overstating passive observations."""

    OBSERVATION = "observation"
    SUSPICIOUS = "suspicious"
    LIKELY = "likely"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NOT_TESTED = "not_tested"


class RiskLevel(StrEnum):
    """Safety classification for a proposed, never-auto-run test."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

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


class ScannerProfile(StrEnum):
    """Capability profile selected for a URL scan."""

    PASSIVE = "passive"
    SAFE = "safe"
    CTF = "ctf"
    LOCAL_LAB = "local_lab"


class ScanStatus(StrEnum):
    """Persisted lifecycle for cancellable scanner jobs."""

    QUEUED = "queued"
    VALIDATING_SCOPE = "validating_scope"
    CRAWLING = "crawling"
    FINGERPRINTING = "fingerprinting"
    PASSIVE_ANALYSIS = "passive_analysis"
    PLANNING_ACTIVE_TESTS = "planning_active_tests"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    ACTIVE_TESTING = "active_testing"
    VERIFYING = "verifying"
    REPORTING = "reporting"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    BLOCKED = "blocked"


class ActiveTestStatus(StrEnum):
    """Approval and execution state for one bounded mutation request."""

    PREVIEW = "preview"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


class CodeProjectStatus(StrEnum):
    """Lifecycle for an inert, uploaded source tree."""

    EMPTY = "empty"
    INDEXED = "indexed"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class StaticFindingStatus(StrEnum):
    """Evidence maturity for source-only findings."""

    STATIC_CANDIDATE = "static_candidate"
    MANUAL_CONFIRMATION_REQUIRED = "manual_confirmation_required"


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
    SCAN_CREATED = "scan.created"
    SCAN_STARTED = "scan.started"
    SCAN_STAGE_CHANGED = "scan.stage_changed"
    SCAN_CANCELLATION_REQUESTED = "scan.cancellation_requested"
    SCAN_COMPLETED = "scan.completed"
    SCAN_CANCELLED = "scan.cancelled"
    SCAN_BLOCKED = "scan.blocked"
    SCAN_FAILED = "scan.failed"
    SCAN_TESTS_PLANNED = "scan.tests_planned"
    SCAN_TESTS_APPROVED = "scan.tests_approved"
    SCAN_TEST_STARTED = "scan.test_started"
    SCAN_TEST_COMPLETED = "scan.test_completed"
    SCAN_TEST_BLOCKED = "scan.test_blocked"
    CODE_PROJECT_CREATED = "code_project.created"
    CODE_PROJECT_UPLOAD_ACCEPTED = "code_project.upload_accepted"
    CODE_PROJECT_UPLOAD_BLOCKED = "code_project.upload_blocked"
    CODE_PROJECT_ANALYZED = "code_project.analyzed"


class VulnerabilityCategory(StrEnum):
    """Initial passive analysis categories."""

    SECURITY_HEADERS = "security_headers"
    CORS = "cors"
    JWT = "jwt"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    OPEN_REDIRECT = "open_redirect"
    AUTHENTICATION = "authentication"
    COMMAND_INJECTION = "command_injection"
    SERVER_SIDE_TEMPLATE_INJECTION = "server_side_template_injection"
    PATH_TRAVERSAL = "path_traversal"
    FILE_INCLUSION = "file_inclusion"


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

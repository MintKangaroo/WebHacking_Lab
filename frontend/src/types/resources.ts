export type WorkspaceMode = "ctf" | "authorized_pentest" | "local_lab";
export type AnalysisMode = "manual_http" | "url_scan" | "source_code" | "hybrid";
export type CodeProjectStatus = "empty" | "indexed" | "analyzing" | "completed" | "failed";

export type NameValue = {
  name: string;
  value: string;
  redacted: boolean;
};

export type NormalizedRequest = {
  method: string;
  scheme: "http" | "https";
  host: string;
  port: number;
  path: string;
  query: NameValue[];
  headers: NameValue[];
  cookies: NameValue[];
  body: string;
  content_type: string | null;
  character_encoding: string;
};

export type NormalizedResponse = {
  status_code: number;
  reason: string;
  headers: NameValue[];
  cookies: NameValue[];
  body: string;
  content_type: string | null;
  character_encoding: string;
  elapsed_ms: number | null;
  redirect_history: Array<{ status_code: number; url: string; location: string | null }>;
  body_hash: string;
  normalized_body_hash: string;
};

export type Workspace = {
  id: string;
  project_id: string;
  name: string;
  mode: WorkspaceMode;
  analysis_mode: AnalysisMode;
  network_execution_enabled: boolean;
  request_budget: number;
  requests_used: number;
  version: number;
  created_at: string;
  updated_at: string;
};

export type ScopeRule = {
  id: string;
  project_id: string;
  scheme: string;
  hostname: string;
  port: number | null;
  path_prefix: string;
  allow_subdomains: boolean;
  max_requests_per_minute: number;
  max_concurrency: number;
  authorization_confirmed: boolean;
  authorization_notes: string;
  created_at: string;
};

export type ProjectSummary = {
  id: string;
  name: string;
  description: string;
  mode: WorkspaceMode;
  version: number;
  workspace_count: number;
  scope_rule_count: number;
  created_at: string;
  updated_at: string;
};

export type ProjectDetail = ProjectSummary & {
  workspaces: Workspace[];
  scope_rules: ScopeRule[];
};

export type ImportedExchange = {
  request: NormalizedRequest;
  response: NormalizedResponse | null;
};

export type ImportResult = {
  exchanges: ImportedExchange[];
  request_ids: string[];
  warnings: string[];
};

export type ScopeDecision = {
  allowed: boolean;
  code: string;
  reason: string;
  normalized_url: string | null;
  hostname: string | null;
  resolved_ips: string[];
  matched_rule_id: string | null;
};

export type HttpResponseRecord = {
  id: string;
  request_id: string;
  status_code: number;
  normalized: NormalizedResponse;
  body_size: number;
  elapsed_ms: number | null;
  created_at: string;
};

export type HttpRequestRecord = {
  id: string;
  workspace_id: string;
  method: string;
  url: string;
  normalized: NormalizedRequest;
  raw_http_redacted: string;
  body_size: number;
  source: string;
  version: number;
  revisions: Array<{
    id: string;
    revision_number: number;
    change_summary: string;
    created_at: string;
  }>;
  responses: HttpResponseRecord[];
  created_at: string;
  updated_at: string;
};

export type RequestExecutionPreview = {
  request_id: string;
  workspace_id: string;
  target_url: string;
  method: "GET" | "HEAD" | "OPTIONS";
  exact_request: string;
  maximum_request_count: number;
  max_response_bytes: number;
  expected_impact: string;
  data_changes: false;
  tls_verification: true;
  scope: ScopeDecision;
  approval_token: string;
  warnings: string[];
};

export type RequestExecutionResult = {
  preview: RequestExecutionPreview;
  response: HttpResponseRecord;
  requests_used: number;
  request_budget: number;
  request_count: number;
};

export type ScannerProfile = "passive" | "safe" | "ctf" | "local_lab";

export type ScanStatus =
  | "queued"
  | "validating_scope"
  | "crawling"
  | "fingerprinting"
  | "passive_analysis"
  | "planning_active_tests"
  | "waiting_for_approval"
  | "active_testing"
  | "verifying"
  | "reporting"
  | "completed"
  | "cancelled"
  | "failed"
  | "blocked";

export type CrawlPolicy = {
  max_depth: number;
  max_pages: number;
  max_requests: number;
  max_response_bytes: number;
  requests_per_second: number;
  concurrency: number;
  include_subdomains: boolean;
  respect_logout_routes: boolean;
  execute_javascript: boolean;
};

export type ActiveTestPolicy = {
  enabled: boolean;
  max_tests: number;
  max_tests_per_parameter: number;
  allow_limited_timing: boolean;
};

export type TechnologyFingerprint = {
  name: string;
  evidence: string;
  confidence: number;
};

export type ScanJob = {
  id: string;
  project_id: string;
  workspace_id: string;
  profile: ScannerProfile;
  target: string;
  status: ScanStatus;
  current_stage: string;
  progress: number;
  request_budget: number;
  requests_used: number;
  endpoints_count: number;
  parameters_count: number;
  findings_count: number;
  cancellation_requested: boolean;
  crawl_policy: CrawlPolicy;
  active_test_policy: ActiveTestPolicy;
  planned_tests_count: number;
  approved_tests_count: number;
  fingerprints: TechnologyFingerprint[];
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
};

export type ScanEndpoint = {
  id: string;
  scan_id: string;
  url: string;
  method: string;
  source: string;
  depth: number;
  fetched: boolean;
  status_code: number | null;
  content_type: string | null;
  title: string | null;
  http_request_id: string | null;
  http_response_id: string | null;
  created_at: string;
};

export type ScanParameter = {
  id: string;
  scan_id: string;
  endpoint_url: string;
  name: string;
  location: string;
  sample_value: string;
  source: string;
  created_at: string;
};

export type ScanFinding = {
  id: string;
  scan_id: string;
  endpoint_url: string;
  analyzer: string;
  category: string;
  title: string;
  summary: string;
  status: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: number;
  evidence: Array<Record<string, unknown>>;
  remediation: string[];
  limitations: string[];
  created_at: string;
};

export type ScanEvent = {
  id: string;
  scan_id: string;
  stage: string;
  level: string;
  message: string;
  details: Record<string, unknown>;
  created_at: string;
};

export type CodeProject = {
  id: string;
  project_id: string;
  name: string;
  description: string;
  authorization_confirmed: boolean;
  authorization_notes: string;
  status: CodeProjectStatus;
  languages: string[];
  frameworks: string[];
  dependency_files: string[];
  warnings: string[];
  total_files: number;
  total_bytes: number;
  secret_findings_count: number;
  analyzed_at: string | null;
  created_at: string;
  updated_at: string;
};

export type CodeFile = {
  id: string;
  relative_path: string;
  language: string;
  size_bytes: number;
  sha256: string;
  secret_findings_count: number;
  warning_codes: string[];
  route_count: number;
};

export type CodeFileContent = CodeFile & {
  content: string;
  redacted: boolean;
  truncated: boolean;
};

export type StaticParameter = {
  name: string;
  location: string;
  required: boolean;
};

export type StaticRoute = {
  id: string;
  code_file_id: string;
  framework: string;
  methods: string[];
  path: string;
  handler_name: string;
  file_path: string;
  line_start: number;
  line_end: number;
  parameters: StaticParameter[];
  authentication: {
    required: boolean;
    mechanisms: string[];
    limitations: string[];
  };
  findings: string[];
};

export type StaticFindingStatus =
  | "static_candidate"
  | "manual_confirmation_required";

export type StaticFlowStep = {
  id: string;
  kind: "source" | "transformation" | "sanitizer" | "sink";
  label: string;
  line: number;
  detail: string;
};

export type StaticFlowEdge = {
  id: string;
  source: string;
  target: string;
  label: string;
};

export type StaticCodeFinding = {
  id: string;
  code_project_id: string;
  code_file_id: string;
  static_route_id: string | null;
  file_path: string;
  route: string | null;
  route_handler: string | null;
  category: string;
  title: string;
  status: StaticFindingStatus;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: number;
  source_label: string;
  sink_label: string;
  parameter: string | null;
  source_line: number;
  sink_line: number;
  sanitizers: string[];
  evidence: string[];
  remediation: {
    summary: string;
    guidance: string[];
    safe_example: string;
    verification: string;
  };
  limitations: string[];
};

export type StaticDataFlow = {
  finding_id: string;
  nodes: StaticFlowStep[];
  edges: StaticFlowEdge[];
};

export type CodeAnalysis = {
  project: CodeProject;
  routes: StaticRoute[];
  analysis_log: string[];
  limitations: string[];
};

export type CodeUploadResult = {
  project: CodeProject;
  files: CodeFile[];
  policy: {
    max_archive_bytes: number;
    max_extracted_bytes: number;
    max_files: number;
    max_single_file_bytes: number;
    max_archive_depth: number;
  };
  execution_performed: false;
};

export type ActiveTestStatus =
  | "preview"
  | "approved"
  | "running"
  | "completed"
  | "inconclusive"
  | "blocked";

export type ScanTestCase = {
  id: string;
  scan_id: string;
  plugin_id: string;
  category: string;
  endpoint_url: string;
  method: string;
  title: string;
  objective: string;
  parameter: string | null;
  mutation_type: string;
  preview_value: string;
  exact_request_preview: string;
  expected_signals: string[];
  success_criteria: string;
  false_positive_notes: string;
  remediation: string[];
  risk_level: "info" | "low" | "medium" | "high";
  maximum_requests: number;
  destructive: boolean;
  requires_confirmation: boolean;
  status: ActiveTestStatus;
  result_status: string | null;
  confidence: number | null;
  evidence: Array<Record<string, unknown>>;
  error_message: string | null;
  approved_at: string | null;
  completed_at: string | null;
  created_at: string;
};

export type VerificationStatus =
  | "observation"
  | "suspicious"
  | "likely"
  | "confirmed"
  | "false_positive"
  | "not_tested";

export type AnalysisResult = {
  analyzer: string;
  category: string;
  title: string;
  summary: string;
  evidence: Array<{ title: string; detail: string; location: string | null }>;
  hypotheses: Array<{ title: string; rationale: string; status: VerificationStatus }>;
  safe_test_cases: Array<{
    title: string;
    objective: string;
    parameter: string | null;
    mutation_type: string;
    preview_value: string;
    expected_signal: string[];
    risk_level: string;
    requires_confirmation: boolean;
    max_requests: number;
    destructive: boolean;
  }>;
  confidence: number;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: VerificationStatus;
  remediation: string[];
  references: Array<{ title: string; url: string }>;
  limitations: string[];
};

export type AnalysisFlow = {
  nodes: Array<{
    id: string;
    label: string;
    status: string;
    detail: string;
    confidence: number | null;
  }>;
  edges: Array<{ id: string; source: string; target: string }>;
};

export type AnalysisRun = {
  id: string;
  request_id: string;
  response_id: string | null;
  status: string;
  results: AnalysisResult[];
  flow: AnalysisFlow;
  created_at: string;
};

export type ResponseDiff = {
  status_changed: boolean;
  baseline_status: number;
  test_status: number;
  header_differences: Array<{ name: string; baseline: string[]; test: string[] }>;
  cookie_changed: boolean;
  body_similarity: number;
  body_size_delta: number;
  elapsed_ms_delta: number | null;
  redirect_changed: boolean;
  json_differences: Array<{ path: string; baseline: unknown; test: unknown }>;
  html_text_similarity: number | null;
  error_patterns_added: string[];
  unified_body_diff: string;
};

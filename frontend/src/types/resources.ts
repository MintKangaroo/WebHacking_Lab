export type WorkspaceMode = "ctf" | "authorized_pentest" | "local_lab";
export type AnalysisMode = "manual_http" | "url_scan" | "source_code" | "hybrid";

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

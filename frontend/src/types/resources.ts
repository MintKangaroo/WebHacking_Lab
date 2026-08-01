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

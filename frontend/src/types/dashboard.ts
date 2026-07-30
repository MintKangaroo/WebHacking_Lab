export type SafetyStatus = {
  mode: "Analysis Only";
  network_execution_enabled: boolean;
  insecure_tls_allowed: boolean;
  max_response_bytes: number;
  global_requests_per_minute: number;
};

export type Metric = {
  label: string;
  value: number;
  delta: number | null;
  trend: "up" | "down" | "neutral";
};

export type SeverityDatum = {
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  count: number;
};

export type RequestVolumeDatum = {
  label: string;
  requests: number;
  blocked: number;
};

export type AnalysisTypeDatum = {
  category: string;
  count: number;
};

export type RecentActivity = {
  id: string;
  kind: "analysis" | "finding" | "scope" | "ctf" | "lab";
  title: string;
  detail: string;
  occurred_at: string;
  status: "completed" | "review" | "blocked" | "active";
};

export type DashboardOverview = {
  workspace_name: string;
  demo_mode: boolean;
  safety: SafetyStatus;
  metrics: Metric[];
  severity_distribution: SeverityDatum[];
  request_volume: RequestVolumeDatum[];
  analysis_types: AnalysisTypeDatum[];
  recent_activity: RecentActivity[];
};

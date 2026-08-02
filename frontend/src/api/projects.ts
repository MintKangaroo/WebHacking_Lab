import { apiGet, apiJson } from "./client";
import type {
  ProjectDetail,
  ProjectSummary,
  ScopeDecision,
  ScopeRule,
  WorkspaceMode,
  Workspace,
} from "../types/resources";

export type CreateProjectInput = {
  name: string;
  description: string;
  mode: WorkspaceMode;
};

export type CreateScopeInput = {
  scheme: "http" | "https";
  hostname: string;
  port: number | null;
  path_prefix: string;
  allow_subdomains: boolean;
  authorization_confirmed: boolean;
  authorization_notes: string;
};

export function getProjects(signal?: AbortSignal) {
  return apiGet<ProjectSummary[]>("/projects", signal);
}

export function getProject(projectId: string, signal?: AbortSignal) {
  return apiGet<ProjectDetail>(`/projects/${projectId}`, signal);
}

export function createProject(input: CreateProjectInput) {
  return apiJson<ProjectDetail, CreateProjectInput>("/projects", "POST", input);
}

export function createScope(projectId: string, input: CreateScopeInput) {
  return apiJson<ScopeRule, CreateScopeInput>(
    `/projects/${projectId}/scope`,
    "POST",
    input,
  );
}

export function checkScope(projectId: string, url: string) {
  return apiJson<ScopeDecision, { url: string }>(
    `/projects/${projectId}/scope/check`,
    "POST",
    { url },
  );
}

export function enableWorkspaceExecution(
  workspaceId: string,
  input: {
    authorization_confirmed: true;
    confirmation_phrase: "ENABLE CONTROLLED REQUESTS";
    expected_use: string;
    version: number;
  },
) {
  return apiJson<Workspace, typeof input>(
    `/workspaces/${workspaceId}/execution/enable`,
    "POST",
    input,
  );
}

export function disableWorkspaceExecution(workspaceId: string, version: number) {
  return apiJson<Workspace, { version: number }>(
    `/workspaces/${workspaceId}/execution/disable`,
    "POST",
    { version },
  );
}

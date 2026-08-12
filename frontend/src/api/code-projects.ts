import { apiForm, apiGet, apiJson } from "./client";
import type {
  CodeAnalysis,
  CodeFile,
  CodeFileContent,
  CodeProject,
  CodeUploadResult,
  StaticCodeFinding,
  StaticDataFlow,
  StaticRoute,
} from "../types/resources";

export function getCodeProjects(projectId?: string, signal?: AbortSignal) {
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  return apiGet<CodeProject[]>(`/code-projects${query}`, signal);
}

export function createCodeProject(input: {
  project_id: string;
  name: string;
  description: string;
  authorization_confirmed: true;
  authorization_notes: string;
  confirmation_phrase: "UPLOAD INERT SOURCE";
}) {
  return apiJson<CodeProject, typeof input>("/code-projects", "POST", input);
}

export function uploadCodeProject(codeProjectId: string, files: File[]) {
  const form = new FormData();
  form.set("code_project_id", codeProjectId);
  for (const file of files) form.append("files", file, file.name);
  return apiForm<CodeUploadResult>("/code-projects/upload", form);
}

export function getCodeFiles(codeProjectId: string, signal?: AbortSignal) {
  return apiGet<CodeFile[]>(`/code-projects/${codeProjectId}/files`, signal);
}

export function getCodeFile(
  codeProjectId: string,
  fileId: string,
  signal?: AbortSignal,
) {
  return apiGet<CodeFileContent>(
    `/code-projects/${codeProjectId}/files/${fileId}`,
    signal,
  );
}

export function getCodeRoutes(codeProjectId: string, signal?: AbortSignal) {
  return apiGet<StaticRoute[]>(`/code-projects/${codeProjectId}/routes`, signal);
}

export function getCodeFindings(codeProjectId: string, signal?: AbortSignal) {
  return apiGet<StaticCodeFinding[]>(`/code-projects/${codeProjectId}/findings`, signal);
}

export function getCodeDataFlows(codeProjectId: string, signal?: AbortSignal) {
  return apiGet<StaticDataFlow[]>(`/code-projects/${codeProjectId}/data-flows`, signal);
}

export function analyzeCodeProject(codeProjectId: string) {
  return apiJson<CodeAnalysis>(`/code-projects/${codeProjectId}/analyze`, "POST");
}

export function getCodeAnalysis(codeProjectId: string, signal?: AbortSignal) {
  return apiGet<CodeAnalysis>(`/code-projects/${codeProjectId}/analysis`, signal);
}

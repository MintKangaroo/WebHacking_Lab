import { apiGet, apiGetText } from "./client";
import type {
  HybridReport,
  ProjectReport,
  ReportFindingDetail,
  ReportSource,
} from "../types/resources";

export function getProjectReport(projectId: string, signal?: AbortSignal) {
  return apiGet<ProjectReport>(`/projects/${projectId}/report`, signal);
}

export function getProjectHybridReport(projectId: string, signal?: AbortSignal) {
  return apiGet<HybridReport>(`/projects/${projectId}/report/hybrid`, signal);
}

export function getProjectReportMarkdown(projectId: string, signal?: AbortSignal) {
  return apiGetText(`/projects/${projectId}/report/markdown`, signal);
}

export function getReportFindingDetail(
  projectId: string,
  source: ReportSource,
  originId: string,
  signal?: AbortSignal,
) {
  return apiGet<ReportFindingDetail>(
    `/projects/${projectId}/report/findings/${source}/${originId}`,
    signal,
  );
}

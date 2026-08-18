import { apiGet, apiGetText } from "./client";
import type { ProjectReport, ReportFindingDetail, ReportSource } from "../types/resources";

export function getProjectReport(projectId: string, signal?: AbortSignal) {
  return apiGet<ProjectReport>(`/projects/${projectId}/report`, signal);
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

import { apiGet, apiJson } from "./client";
import type {
  CrawlPolicy,
  ScanEndpoint,
  ScanEvent,
  ScanFinding,
  ScanJob,
  ScanParameter,
} from "../types/resources";

export type CreatePassiveScanInput = {
  project_id: string;
  workspace_id: string;
  target: string;
  profile: "passive";
  crawl_policy: CrawlPolicy;
  authorization_confirmed: true;
  confirmation_phrase: "START PASSIVE SCAN";
  expected_use: string;
};

export function getScans(projectId?: string, signal?: AbortSignal) {
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  return apiGet<ScanJob[]>(`/scans${query}`, signal);
}

export function getScan(scanId: string, signal?: AbortSignal) {
  return apiGet<ScanJob>(`/scans/${scanId}`, signal);
}

export function createPassiveScan(input: CreatePassiveScanInput) {
  return apiJson<ScanJob, CreatePassiveScanInput>("/scans", "POST", input);
}

export function cancelScan(scanId: string) {
  return apiJson<
    { id: string; cancellation_requested: boolean; status: string },
    undefined
  >(`/scans/${scanId}/cancel`, "POST");
}

export function getScanEndpoints(scanId: string, signal?: AbortSignal) {
  return apiGet<ScanEndpoint[]>(`/scans/${scanId}/endpoints`, signal);
}

export function getScanParameters(scanId: string, signal?: AbortSignal) {
  return apiGet<ScanParameter[]>(`/scans/${scanId}/parameters`, signal);
}

export function getScanFindings(scanId: string, signal?: AbortSignal) {
  return apiGet<ScanFinding[]>(`/scans/${scanId}/findings`, signal);
}

export function getScanEvents(scanId: string, signal?: AbortSignal) {
  return apiGet<ScanEvent[]>(`/scans/${scanId}/events`, signal);
}

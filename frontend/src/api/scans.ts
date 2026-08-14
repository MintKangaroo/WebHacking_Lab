import { apiGet, apiJson } from "./client";
import type {
  CrawlPolicy,
  ScanEndpoint,
  ScanEvent,
  ScanFinding,
  ScanJob,
  ScanParameter,
  ScannerProfile,
  ScanStatus,
  ScanTestCase,
} from "../types/resources";

export type CreateScanInput = {
  project_id: string;
  workspace_id: string;
  target: string;
  profile: Extract<ScannerProfile, "passive" | "safe" | "ctf">;
  crawl_policy: CrawlPolicy;
  active_test_policy: {
    enabled: boolean;
    max_tests: number;
    max_tests_per_parameter: number;
    allow_limited_timing: false;
  };
  authorization_confirmed: true;
  confirmation_phrase: "START PASSIVE SCAN" | "START SAFE SCAN" | "START CTF SCAN";
  expected_use: string;
};

export function getScans(projectId?: string, signal?: AbortSignal) {
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  return apiGet<ScanJob[]>(`/scans${query}`, signal);
}

export function getScan(scanId: string, signal?: AbortSignal) {
  return apiGet<ScanJob>(`/scans/${scanId}`, signal);
}

export function createScan(input: CreateScanInput) {
  return apiJson<ScanJob, CreateScanInput>("/scans", "POST", input);
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

export function getScanTests(scanId: string, signal?: AbortSignal) {
  return apiGet<ScanTestCase[]>(`/scans/${scanId}/tests`, signal);
}

export function approveScanTests(scanId: string, testIds: string[]) {
  return apiJson<
    { scan_id: string; approved_test_ids: string[]; status: ScanStatus },
    {
      test_ids: string[];
      authorization_confirmed: true;
      confirmation_phrase: "APPROVE SELECTED SAFE TESTS";
    }
  >(`/scans/${scanId}/approve-tests`, "POST", {
    test_ids: testIds,
    authorization_confirmed: true,
    confirmation_phrase: "APPROVE SELECTED SAFE TESTS",
  });
}

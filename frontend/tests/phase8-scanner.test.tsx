import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../src/app";
import type { ProjectDetail, ProjectSummary, ScanJob } from "../src/types/resources";

const projectId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const workspaceId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const scanId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

const projectSummary: ProjectSummary = {
  id: projectId,
  name: "Authorized Storefront",
  description: "Written authorization recorded",
  mode: "authorized_pentest",
  version: 1,
  workspace_count: 1,
  scope_rule_count: 1,
  created_at: "2026-08-02T00:00:00Z",
  updated_at: "2026-08-02T00:00:00Z",
};

const projectDetail: ProjectDetail = {
  ...projectSummary,
  workspaces: [
    {
      id: workspaceId,
      project_id: projectId,
      name: "Primary Workspace",
      mode: "authorized_pentest",
      analysis_mode: "url_scan",
      network_execution_enabled: true,
      request_budget: 50,
      requests_used: 4,
      version: 2,
      created_at: "2026-08-02T00:00:00Z",
      updated_at: "2026-08-02T00:00:00Z",
    },
  ],
  scope_rules: [
    {
      id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
      project_id: projectId,
      scheme: "https",
      hostname: "authorized.example",
      port: 443,
      path_prefix: "/review",
      allow_subdomains: false,
      max_requests_per_minute: 10,
      max_concurrency: 1,
      authorization_confirmed: true,
      authorization_notes: "Signed assessment scope",
      created_at: "2026-08-02T00:00:00Z",
    },
  ],
};

const scan: ScanJob = {
  id: scanId,
  project_id: projectId,
  workspace_id: workspaceId,
  profile: "passive",
  target: "https://authorized.example/review",
  status: "crawling",
  current_stage: "Crawling",
  progress: 0.42,
  request_budget: 30,
  requests_used: 6,
  endpoints_count: 2,
  parameters_count: 1,
  findings_count: 1,
  cancellation_requested: false,
  crawl_policy: {
    max_depth: 2,
    max_pages: 20,
    max_requests: 30,
    max_response_bytes: 2_000_000,
    requests_per_second: 1,
    concurrency: 1,
    include_subdomains: false,
    respect_logout_routes: true,
    execute_javascript: false,
  },
  fingerprints: [
    { name: "FastAPI", evidence: "Server response header", confidence: 0.7 },
  ],
  error_message: null,
  started_at: "2026-08-02T00:01:00Z",
  finished_at: null,
  created_at: "2026-08-02T00:01:00Z",
  updated_at: "2026-08-02T00:01:05Z",
};

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.history.pushState({}, "", "/");
});

describe("Phase 8 guarded passive scanner", () => {
  it("reviews, starts, monitors, and cancels an authorized external scan", async () => {
    window.history.pushState({}, "", "/scans");
    let createdBody: Record<string, unknown> | undefined;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = requestUrl(input);
      const path = new URL(url, window.location.origin).pathname;
      if (path === "/api/projects") return jsonResponse([projectSummary]);
      if (path === `/api/projects/${projectId}`) return jsonResponse(projectDetail);
      if (path === "/api/scans" && init?.method === "POST") {
        if (typeof init.body !== "string") throw new Error("Expected a JSON request body");
        createdBody = JSON.parse(init.body) as Record<string, unknown>;
        return jsonResponse(scan, 202);
      }
      if (path === "/api/scans") return jsonResponse(createdBody ? [scan] : []);
      if (path === `/api/scans/${scanId}`) return jsonResponse(scan);
      if (path === `/api/scans/${scanId}/endpoints`) {
        return jsonResponse([
          {
            id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            scan_id: scanId,
            url: "https://authorized.example/review/products?page=1",
            method: "GET",
            source: "html-link",
            depth: 1,
            fetched: true,
            status_code: 200,
            content_type: "text/html",
            title: "Products",
            http_request_id: null,
            http_response_id: null,
            created_at: "2026-08-02T00:01:02Z",
          },
        ]);
      }
      if (path === `/api/scans/${scanId}/parameters`) {
        return jsonResponse([
          {
            id: "ffffffff-ffff-4fff-8fff-ffffffffffff",
            scan_id: scanId,
            endpoint_url: "https://authorized.example/review/products?page=1",
            name: "page",
            location: "query",
            sample_value: "1",
            source: "html-link",
            created_at: "2026-08-02T00:01:02Z",
          },
        ]);
      }
      if (path === `/api/scans/${scanId}/findings`) {
        return jsonResponse([
          {
            id: "11111111-1111-4111-8111-111111111111",
            scan_id: scanId,
            endpoint_url: "https://authorized.example/review",
            analyzer: "security-header-analyzer",
            category: "security_header_misconfiguration",
            title: "Security headers need review",
            summary: "One or more response controls were not observed.",
            status: "observation",
            severity: "low",
            confidence: 0.6,
            evidence: [],
            remediation: [],
            limitations: [],
            created_at: "2026-08-02T00:01:03Z",
          },
        ]);
      }
      if (path === `/api/scans/${scanId}/events`) {
        return jsonResponse([
          {
            id: "22222222-2222-4222-8222-222222222222",
            scan_id: scanId,
            stage: "Crawling",
            level: "info",
            message: "Fetched one approved page.",
            details: {},
            created_at: "2026-08-02T00:01:03Z",
          },
        ]);
      }
      if (path === `/api/scans/${scanId}/cancel`) {
        return jsonResponse({ id: scanId, cancellation_requested: true, status: "crawling" });
      }
      return jsonResponse({ message: `Unhandled ${path}` }, 404);
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    expect(await screen.findByRole("heading", { name: "Passive URL Scanner" })).toBeInTheDocument();
    await screen.findByRole("option", { name: "Primary Workspace" });

    await userEvent.clear(screen.getByLabelText("Starting URL"));
    await userEvent.type(
      screen.getByLabelText("Starting URL"),
      "https://authorized.example/review",
    );
    await userEvent.click(screen.getByLabelText("Confirm authorization"));
    await userEvent.click(screen.getByRole("button", { name: "Start passive scan" }));

    await waitFor(() => expect(createdBody).toBeDefined());
    expect(createdBody).toMatchObject({
      project_id: projectId,
      workspace_id: workspaceId,
      target: "https://authorized.example/review",
      profile: "passive",
      authorization_confirmed: true,
      confirmation_phrase: "START PASSIVE SCAN",
    });
    expect(await screen.findByText(/authorized\.example\/review\/products\?page=1/)).toBeInTheDocument();
    expect(screen.getByText("FastAPI")).toBeInTheDocument();
    expect(screen.getByText("6/30")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Stop scan" }));
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/scans/cccccccc-cccc-4ccc-8ccc-cccccccccccc/cancel",
        expect.objectContaining({ method: "POST" }),
      );
    });
  });
});

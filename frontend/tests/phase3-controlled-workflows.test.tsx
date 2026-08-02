import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../src/app";
import type {
  HttpRequestRecord,
  NormalizedRequest,
  NormalizedResponse,
  ProjectDetail,
  ProjectSummary,
} from "../src/types/resources";

vi.mock("@xyflow/react", () => ({
  ReactFlow: ({
    nodes,
    onNodeClick,
    children,
  }: {
    nodes: Array<{ id: string; data: { label: string } }>;
    onNodeClick: (event: unknown, node: { id: string }) => void;
    children: ReactNode;
  }) => (
    <div data-testid="analysis-flow">
      {nodes.map((node) => (
        <button key={node.id} type="button" onClick={() => onNodeClick({}, node)}>
          {node.data.label}
        </button>
      ))}
      {children}
    </div>
  ),
  Background: () => null,
  Controls: () => null,
}));

const projectId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const workspaceId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const requestId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const baselineResponseId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const executedResponseId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

const request: NormalizedRequest = {
  method: "GET",
  scheme: "https",
  host: "authorized.example",
  port: 443,
  path: "/allowed",
  query: [{ name: "q", value: "demo", redacted: false }],
  headers: [{ name: "Authorization", value: "[REDACTED]", redacted: true }],
  cookies: [],
  body: "",
  content_type: null,
  character_encoding: "utf-8",
};

function normalizedResponse(status = 200, body = "baseline"): NormalizedResponse {
  return {
    status_code: status,
    reason: status === 200 ? "OK" : "Error",
    headers: [],
    cookies: [],
    body,
    content_type: "text/plain",
    character_encoding: "utf-8",
    elapsed_ms: 4,
    redirect_history: [],
    body_hash: `${status}-hash`,
    normalized_body_hash: `${status}-normalized-hash`,
  };
}

const projectSummary: ProjectSummary = {
  id: projectId,
  name: "Authorized External Review",
  description: "Written permission recorded",
  mode: "authorized_pentest",
  version: 1,
  workspace_count: 1,
  scope_rule_count: 1,
  created_at: "2026-08-02T00:00:00Z",
  updated_at: "2026-08-02T00:00:00Z",
};

function projectDetail(enabled = true): ProjectDetail {
  return {
    ...projectSummary,
    workspaces: [
      {
        id: workspaceId,
        project_id: projectId,
        name: "Primary Workspace",
        mode: "authorized_pentest",
        analysis_mode: "manual_http",
        network_execution_enabled: enabled,
        request_budget: 10,
        requests_used: 0,
        version: enabled ? 2 : 1,
        created_at: "2026-08-02T00:00:00Z",
        updated_at: "2026-08-02T00:00:00Z",
      },
    ],
    scope_rules: [
      {
        id: "ffffffff-ffff-4fff-8fff-ffffffffffff",
        project_id: projectId,
        scheme: "https",
        hostname: "authorized.example",
        port: 443,
        path_prefix: "/allowed",
        allow_subdomains: false,
        max_requests_per_minute: 10,
        max_concurrency: 1,
        authorization_confirmed: true,
        authorization_notes: "Written assessment authorization",
        created_at: "2026-08-02T00:00:00Z",
      },
    ],
  };
}

const storedRequest: HttpRequestRecord = {
  id: requestId,
  workspace_id: workspaceId,
  method: "GET",
  url: "https://authorized.example/allowed?q=demo",
  normalized: request,
  raw_http_redacted: "GET /allowed?q=demo HTTP/1.1",
  body_size: 0,
  source: "curl",
  version: 1,
  revisions: [],
  responses: [
    {
      id: baselineResponseId,
      request_id: requestId,
      status_code: 200,
      normalized: normalizedResponse(),
      body_size: 8,
      elapsed_ms: 4,
      created_at: "2026-08-02T00:00:00Z",
    },
  ],
  created_at: "2026-08-02T00:00:00Z",
  updated_at: "2026-08-02T00:00:00Z",
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

describe("Phase 3 controlled workflows", () => {
  it("reviews, sends, analyzes, and diffs an authorized external request", async () => {
    window.history.pushState({}, "", "/repeater");
    const executedResponse = {
      id: executedResponseId,
      request_id: requestId,
      status_code: 500,
      normalized: normalizedResponse(500, "changed SQL syntax"),
      body_size: 18,
      elapsed_ms: 7,
      created_at: "2026-08-02T00:01:00Z",
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestUrl(input);
      if (path.endsWith("/projects") && init?.method === "GET") {
        return jsonResponse([projectSummary]);
      }
      if (path.endsWith(`/projects/${projectId}`)) return jsonResponse(projectDetail());
      if (path.endsWith("/requests/import/curl")) {
        return jsonResponse({
          exchanges: [{ request, response: normalizedResponse() }],
          request_ids: [requestId],
          warnings: [],
        });
      }
      if (path.endsWith(`/requests/${requestId}`) && init?.method === "GET") {
        return jsonResponse(storedRequest);
      }
      if (path.endsWith(`/requests/${requestId}/execute/preview`)) {
        return jsonResponse({
          request_id: requestId,
          workspace_id: workspaceId,
          target_url: "https://authorized.example/allowed?q=demo",
          method: "GET",
          exact_request: "GET /allowed?q=demo HTTP/1.1\r\nHost: authorized.example",
          maximum_request_count: 5,
          expected_impact: "Read-only retrieval without credentials.",
          data_changes: false,
          tls_verification: true,
          scope: {
            allowed: true,
            code: "allowed",
            reason: "URL and DNS passed",
            normalized_url: "https://authorized.example:443/allowed",
            hostname: "authorized.example",
            resolved_ips: ["93.184.216.34"],
            matched_rule_id: "ffffffff-ffff-4fff-8fff-ffffffffffff",
          },
          approval_token: "a".repeat(64),
          warnings: ["Credentials were omitted"],
        });
      }
      if (path.endsWith(`/requests/${requestId}/execute`)) {
        return jsonResponse(
          {
            preview: {},
            response: executedResponse,
            requests_used: 1,
            request_budget: 10,
          },
          201,
        );
      }
      if (path.endsWith("/analysis")) {
        const statuses = ["observation", "suspicious", "likely", "not_tested"];
        return jsonResponse(
          {
            id: "12121212-1212-4212-8212-121212121212",
            request_id: requestId,
            response_id: executedResponseId,
            status: "completed",
            results: statuses.map((status, index) => ({
              analyzer: `analyzer-${index}`,
              category: `category-${index}`,
              title: `Analysis ${index + 1}`,
              summary: "Passive evidence only",
              evidence: [],
              hypotheses: [],
              safe_test_cases: [],
              confidence: 0.7,
              severity: index === 2 ? "high" : "low",
              status,
              remediation: [],
              references: [],
              limitations: [],
            })),
            flow: {
              nodes: [
                { id: "normalize", label: "Normalize & Redact", status: "confirmed", detail: "Masked", confidence: 1 },
                { id: "passive", label: "Passive Analysis", status: "confirmed", detail: "Completed", confidence: 1 },
                { id: "result-0", label: "Candidate", status: "suspicious", detail: "Review", confidence: 0.7 },
              ],
              edges: [
                { id: "normalize-passive", source: "normalize", target: "passive" },
                { id: "passive-result", source: "passive", target: "result-0" },
              ],
            },
            created_at: "2026-08-02T00:02:00Z",
          },
          201,
        );
      }
      if (path.endsWith("/diff")) {
        return jsonResponse({
          baseline_response_id: baselineResponseId,
          test_response_id: executedResponseId,
          result: {
            status_changed: true,
            baseline_status: 200,
            test_status: 500,
            header_differences: [],
            cookie_changed: false,
            body_similarity: 0.4,
            body_size_delta: 10,
            elapsed_ms_delta: 3,
            redirect_changed: false,
            json_differences: [],
            html_text_similarity: null,
            error_patterns_added: ["sql_error"],
            unified_body_diff: "-baseline\n+changed SQL syntax",
          },
        });
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    await screen.findByText("Normalized preview appears here");
    await screen.findByRole("option", { name: "Authorized External Review" });
    await user.selectOptions(screen.getByLabelText("Project"), projectId);
    await user.selectOptions(await screen.findByLabelText("Workspace"), workspaceId);
    await user.click(screen.getByLabelText("Save for analysis"));
    await user.click(screen.getByRole("button", { name: "Import & save" }));
    expect(await screen.findByText("Normalized request")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Review exact request" }));
    expect(await screen.findByText("Final approval · no automatic tests")).toBeInTheDocument();
    expect(screen.getByText(/Credentials were omitted/)).toBeInTheDocument();
    await user.click(screen.getByLabelText(/I reviewed the exact request/));
    await user.click(screen.getByRole("button", { name: "Send controlled request" }));
    expect(await screen.findByText("Imported response · 500")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Run 6 analyzers" }));
    expect(await screen.findByText("Passive analysis workflow")).toBeInTheDocument();
    expect(screen.getByTestId("analysis-flow")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Candidate" }));
    expect(screen.getByText("Confidence 70%")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Compare last 2" }));
    expect(await screen.findByText("Response diff")).toBeInTheDocument();
    expect(screen.getByText("Similarity 40.0%")).toBeInTheDocument();
  });

  it("registers external scope and toggles workspace execution", async () => {
    window.history.pushState({}, "", `/projects/${projectId}`);
    let enabled = false;
    let scopeBody: Record<string, unknown> | null = null;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestUrl(input);
      if (path.endsWith(`/projects/${projectId}`)) return jsonResponse(projectDetail(enabled));
      if (path.endsWith(`/workspaces/${workspaceId}/execution/enable`)) {
        enabled = true;
        return jsonResponse(projectDetail(true).workspaces[0]);
      }
      if (path.endsWith(`/workspaces/${workspaceId}/execution/disable`)) {
        enabled = false;
        return jsonResponse(projectDetail(false).workspaces[0]);
      }
      if (path.endsWith(`/projects/${projectId}/scope`)) {
        if (typeof init?.body !== "string") throw new Error("Expected a JSON request body");
        scopeBody = JSON.parse(init.body) as Record<string, unknown>;
        return jsonResponse(projectDetail().scope_rules[0], 201);
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    await screen.findByText("Scope registry");
    await screen.findByRole("button", { name: "Enable controlled requests" });
    await user.type(
      screen.getByLabelText("Execution purpose for Primary Workspace"),
      "Authorized external read-only validation",
    );
    await user.click(screen.getByLabelText(/I confirm the target is authorized/));
    await user.click(screen.getByRole("button", { name: "Enable controlled requests" }));
    expect(await screen.findByRole("button", { name: "Disable immediately" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Disable immediately" }));
    expect(await screen.findByRole("button", { name: "Enable controlled requests" })).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Scope scheme"), "http");
    await user.type(screen.getByLabelText("External hostname"), "ctf.example");
    await user.type(screen.getByLabelText("Scope port"), "8080");
    await user.clear(screen.getByLabelText("Scope path"));
    await user.type(screen.getByLabelText("Scope path"), "/challenge");
    await user.type(screen.getByLabelText("Authorization notes"), "Organizer-approved CTF scope");
    await user.click(screen.getByLabelText(/I confirm that I own this system/));
    await user.click(screen.getByRole("button", { name: "Register external scope" }));
    await waitFor(() => expect(scopeBody).not.toBeNull());
    expect(scopeBody).toMatchObject({
      scheme: "http",
      hostname: "ctf.example",
      port: 8080,
      path_prefix: "/challenge",
      authorization_confirmed: true,
    });
  });
});

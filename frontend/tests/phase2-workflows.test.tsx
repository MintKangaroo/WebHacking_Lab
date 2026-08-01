import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../src/app";
import type { ProjectDetail, ProjectSummary } from "../src/types/resources";

const projectSummary: ProjectSummary = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "Local Shop Review",
  description: "Authorized local training project",
  mode: "local_lab",
  version: 1,
  workspace_count: 1,
  scope_rule_count: 2,
  created_at: "2026-08-02T00:00:00Z",
  updated_at: "2026-08-02T00:00:00Z",
};

const projectDetail: ProjectDetail = {
  ...projectSummary,
  workspaces: [
    {
      id: "22222222-2222-4222-8222-222222222222",
      project_id: projectSummary.id,
      name: "Primary Workspace",
      mode: "local_lab",
      analysis_mode: "manual_http",
      network_execution_enabled: false,
      request_budget: 100,
      requests_used: 0,
      version: 1,
      created_at: "2026-08-02T00:00:00Z",
      updated_at: "2026-08-02T00:00:00Z",
    },
  ],
  scope_rules: [
    {
      id: "33333333-3333-4333-8333-333333333333",
      project_id: projectSummary.id,
      scheme: "http",
      hostname: "127.0.0.1",
      port: null,
      path_prefix: "/",
      allow_subdomains: false,
      max_requests_per_minute: 10,
      max_concurrency: 2,
      authorization_confirmed: false,
      authorization_notes: "Built-in loopback scope",
      created_at: "2026-08-02T00:00:00Z",
    },
  ],
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

describe("Phase 2 workflows", () => {
  it("creates an API-backed analysis-only project", async () => {
    window.history.pushState({}, "", "/projects");
    let created = false;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestUrl(input);
      if (path.endsWith("/projects") && init?.method === "POST") {
        created = true;
        return jsonResponse(projectDetail, 201);
      }
      if (path.endsWith("/projects")) {
        return jsonResponse(created ? [projectSummary] : []);
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Project name"), "Local Shop Review");
    await user.type(screen.getByLabelText("Description"), "Authorized local training project");
    await user.click(screen.getByRole("button", { name: "Create analysis project" }));

    expect(await screen.findByText("Local Shop Review")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/projects"),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("shows a blocked Scope Guard decision without sending a target request", async () => {
    window.history.pushState({}, "", `/projects/${projectSummary.id}`);
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestUrl(input);
      if (path.endsWith("/scope/check") && init?.method === "POST") {
        return jsonResponse({
          allowed: false,
          code: "metadata_blocked",
          reason: "Cloud metadata hostnames are always blocked",
          normalized_url: "http://169.254.169.254:80/latest/meta-data",
          hostname: "169.254.169.254",
          resolved_ips: [],
          matched_rule_id: null,
        });
      }
      if (path.endsWith(`/projects/${projectSummary.id}`)) return jsonResponse(projectDetail);
      throw new Error(`Unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    await screen.findByText("Scope registry");
    const urlInput = screen.getByLabelText("URL to check");
    await user.clear(urlInput);
    await user.type(urlInput, "http://169.254.169.254/latest/meta-data");
    await user.click(screen.getByRole("button", { name: "Check without sending" }));

    expect(await screen.findByText("metadata_blocked")).toBeInTheDocument();
    expect(screen.getByText("Cloud metadata hostnames are always blocked")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalledWith(
      "http://169.254.169.254/latest/meta-data",
      expect.anything(),
    );
  });

  it("imports cURL as a redacted preview", async () => {
    window.history.pushState({}, "", "/repeater");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestUrl(input);
      if (path.endsWith("/requests/import/curl") && init?.method === "POST") {
        return jsonResponse({
          exchanges: [
            {
              request: {
                method: "GET",
                scheme: "http",
                host: "127.0.0.1",
                port: 5000,
                path: "/search",
                query: [{ name: "q", value: "demo", redacted: false }],
                headers: [{ name: "Authorization", value: "[REDACTED]", redacted: true }],
                cookies: [],
                body: "",
                content_type: null,
                character_encoding: "utf-8",
              },
              response: null,
            },
          ],
          request_ids: [],
          warnings: [],
        });
      }
      if (path.endsWith("/projects")) return jsonResponse([]);
      throw new Error(`Unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    await screen.findByText("Normalized preview appears here");
    await user.click(screen.getByRole("button", { name: "Import safely" }));

    expect(await screen.findByText("Normalized request")).toBeInTheDocument();
    expect(screen.getByText(/\[REDACTED\]/)).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
  });

  it("imports a HAR response without replaying the request", async () => {
    window.history.pushState({}, "", "/repeater");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = requestUrl(input);
      if (path.endsWith("/requests/import/har") && init?.method === "POST") {
        return jsonResponse({
          exchanges: [
            {
              request: {
                method: "GET",
                scheme: "http",
                host: "localhost",
                port: 80,
                path: "/profile",
                query: [],
                headers: [],
                cookies: [],
                body: "",
                content_type: null,
                character_encoding: "utf-8",
              },
              response: {
                status_code: 200,
                reason: "OK",
                headers: [],
                cookies: [],
                body: '{"token":"[REDACTED]"}',
                content_type: "application/json",
                character_encoding: "utf-8",
                elapsed_ms: 8.2,
                redirect_history: [],
                body_hash: "hash",
                normalized_body_hash: "hash",
              },
            },
          ],
          request_ids: [],
          warnings: [],
        });
      }
      if (path.endsWith("/projects")) return jsonResponse([]);
      throw new Error(`Unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    await user.click(await screen.findByRole("button", { name: "har" }));
    fireEvent.change(screen.getByLabelText("HAR input"), {
      target: { value: '{"log":{"entries":[]}}' },
    });
    await user.click(screen.getByRole("button", { name: "Import safely" }));

    expect(await screen.findByText("Imported response · 200")).toBeInTheDocument();
    expect(screen.getAllByText(/\[REDACTED\]/).length).toBeGreaterThan(0);
  });
});

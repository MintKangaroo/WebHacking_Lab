import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../src/app";

const projectId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const workspaceId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const overview = {
  safety: {
    mode: "Controlled Execution",
    network_execution_enabled: true,
    ctf_mode_enabled: true,
    insecure_tls_allowed: false,
    max_response_bytes: 2_000_000,
    global_requests_per_minute: 30,
  },
};

const projects = [
  {
    id: projectId,
    name: "Lab Project",
    description: "",
    mode: "local_lab",
    version: 1,
    workspace_count: 1,
    scope_rule_count: 0,
    created_at: "2026-08-21T00:00:00Z",
    updated_at: "2026-08-21T00:00:00Z",
  },
];

const projectDetail = {
  ...projects[0],
  workspaces: [
    {
      id: workspaceId,
      project_id: projectId,
      name: "Primary Workspace",
      mode: "local_lab",
      analysis_mode: "manual_http",
      network_execution_enabled: true,
      request_budget: 100,
      requests_used: 0,
      version: 1,
      created_at: "2026-08-21T00:00:00Z",
      updated_at: "2026-08-21T00:00:00Z",
    },
  ],
  scope_rules: [],
};

function response(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function pathOf(input: RequestInfo | URL) {
  const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  return new URL(raw, window.location.origin).pathname;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.history.pushState({}, "", "/");
});

describe("Scan plan lab pre-fill", () => {
  it("seeds the target and offers to register the lab host in scope", async () => {
    const scopeCheckCalls: unknown[] = [];
    const scopeCreateCalls: unknown[] = [];
    window.history.pushState(
      {},
      "",
      "/scans?labId=sqli&profile=ctf&scopeScheme=http&scopeHost=lab-sqli&scopePort=5000&target=" +
        encodeURIComponent("http://lab-sqli:5000/products?id=1"),
    );

    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input);
      if (path === "/api/dashboard/overview") return Promise.resolve(response(overview));
      if (path === "/api/projects") return Promise.resolve(response(projects));
      if (path === `/api/projects/${projectId}`) return Promise.resolve(response(projectDetail));
      if (path === `/api/projects/${projectId}/scope/check`) {
        scopeCheckCalls.push(init?.body);
        return Promise.resolve(
          response({
            allowed: false,
            code: "out_of_scope",
            reason: "No matching scope rule",
            normalized_url: "http://lab-sqli:5000/products",
            hostname: "lab-sqli",
            resolved_ips: [],
            matched_rule_id: null,
          }),
        );
      }
      if (path === `/api/projects/${projectId}/scope` && init?.method === "POST") {
        scopeCreateCalls.push(init?.body);
        return Promise.resolve(
          response({ id: "scope-1", project_id: projectId, hostname: "lab-sqli", port: 5000 }),
        );
      }
      if (path === "/api/scans") return Promise.resolve(response([]));
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    const target = await screen.findByLabelText<HTMLInputElement>("Starting URL");
    await waitFor(() => expect(target.value).toBe("http://lab-sqli:5000/products?id=1"));
    expect(screen.getByText(/Lab target/i)).toBeInTheDocument();

    const addButton = await screen.findByRole("button", { name: /Add lab host to scope/i });
    await userEvent.click(addButton);

    await waitFor(() => expect(scopeCreateCalls.length).toBe(1));
    const body = JSON.parse(String(scopeCreateCalls[0])) as {
      hostname: string;
      port: number;
      authorization_confirmed: boolean;
    };
    expect(body.hostname).toBe("lab-sqli");
    expect(body.port).toBe(5000);
    expect(body.authorization_confirmed).toBe(true);
    expect(scopeCheckCalls.length).toBeGreaterThan(0);
  });
});

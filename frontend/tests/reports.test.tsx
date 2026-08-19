import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../src/app";
import type {
  ProjectReport,
  ProjectSummary,
  ReportFindingDetail,
} from "../src/types/resources";

const projectId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

const project: ProjectSummary = {
  id: projectId,
  name: "Report Target",
  description: "Consolidated review",
  mode: "ctf",
  version: 1,
  workspace_count: 0,
  scope_rule_count: 0,
  created_at: "2026-08-18T00:00:00Z",
  updated_at: "2026-08-18T00:00:00Z",
};

const report: ProjectReport = {
  project_id: projectId,
  project_name: "Report Target",
  generated_at: "2026-08-18T00:00:00Z",
  summary: {
    total: 2,
    by_severity: { critical: 1, high: 1 },
    by_category: { security_headers: 1, sql_injection: 1 },
    by_source: { scanner: 1, static: 1 },
    by_status: { confirmed: 1, static_candidate: 1 },
  },
  findings: [
    {
      source: "scanner",
      origin_id: "11111111-1111-4111-8111-111111111111",
      category: "security_headers",
      title: "Missing HSTS",
      severity: "critical",
      status: "confirmed",
      confidence: 0.9,
      location: "http://lab.test/login",
      detail: "No Strict-Transport-Security header.",
    },
    {
      source: "static",
      origin_id: "22222222-2222-4222-8222-222222222222",
      category: "sql_injection",
      title: "Potential SQL Injection",
      severity: "high",
      status: "static_candidate",
      confidence: 0.9,
      location: "app.py:5",
      detail: "request.args['id'] → cursor.execute",
    },
  ],
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

const staticDetail: ReportFindingDetail = {
  source: "static",
  origin_id: "22222222-2222-4222-8222-222222222222",
  category: "sql_injection",
  title: "Potential SQL Injection",
  severity: "high",
  status: "static_candidate",
  confidence: 0.9,
  location: "app.py:5",
  summary: "request.args['id'] → cursor.execute",
  flow_steps: [
    { kind: "source", label: "request.args['id']", line: 3, detail: "Untrusted input." },
    { kind: "sink", label: "cursor.execute", line: 5, detail: "Reaches SQL." },
  ],
  evidence: ["Source observed at line 3."],
  remediation: ["Use parameter binding."],
  safe_example: "cursor.execute('... = ?', (item_id,))",
  limitations: ["Static analysis does not prove runtime reachability."],
};

describe("Findings report page", () => {
  it("bundles static and scanner findings for the selected project", async () => {
    window.history.pushState({}, "", "/reports");
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (path === "/api/projects") return Promise.resolve(response([project]));
      if (path === `/api/projects/${projectId}/report`) return Promise.resolve(response(report));
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByText("Missing HSTS")).toBeInTheDocument();
    expect(screen.getByText("Potential SQL Injection")).toBeInTheDocument();
    expect(screen.getByText("app.py:5")).toBeInTheDocument();
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        `/api/projects/${projectId}/report`,
        expect.anything(),
      );
    });
  });

  it("drills into a finding to show its flow and remediation", async () => {
    window.history.pushState({}, "", "/reports");
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (path === "/api/projects") return Promise.resolve(response([project]));
      if (path === `/api/projects/${projectId}/report`) return Promise.resolve(response(report));
      if (
        path ===
        `/api/projects/${projectId}/report/findings/static/${staticDetail.origin_id}`
      ) {
        return Promise.resolve(response(staticDetail));
      }
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await userEvent.click(await screen.findByText("Potential SQL Injection"));

    expect(await screen.findByText("Data flow")).toBeInTheDocument();
    expect(screen.getByText("Use parameter binding.")).toBeInTheDocument();
    expect(screen.getByText(/cursor.execute\('... = \?'/)).toBeInTheDocument();
  });

  it("filters findings by source and search text", async () => {
    window.history.pushState({}, "", "/reports");
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (path === "/api/projects") return Promise.resolve(response([project]));
      if (path === `/api/projects/${projectId}/report`) return Promise.resolve(response(report));
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    expect(await screen.findByText("Missing HSTS")).toBeInTheDocument();

    // Filtering to static findings hides the scanner finding.
    await userEvent.selectOptions(screen.getByLabelText("Filter by source"), "static");
    expect(screen.queryByText("Missing HSTS")).not.toBeInTheDocument();
    expect(screen.getByText("Potential SQL Injection")).toBeInTheDocument();

    // A non-matching search hides everything and shows the empty-filter message.
    await userEvent.type(screen.getByLabelText("Search findings"), "nonexistent");
    expect(await screen.findByText(/No findings match the current filters/i)).toBeInTheDocument();
  });

  it("shows an empty state when a project has no findings", async () => {
    window.history.pushState({}, "", "/reports");
    const empty: ProjectReport = {
      ...report,
      summary: { total: 0, by_severity: {}, by_category: {}, by_source: {}, by_status: {} },
      findings: [],
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (path === "/api/projects") return Promise.resolve(response([project]));
      if (path === `/api/projects/${projectId}/report`) return Promise.resolve(response(empty));
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(
      await screen.findByText(/No static or scanner findings were recorded/i),
    ).toBeInTheDocument();
  });
});

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../src/app";
import type {
  CodeAnalysis,
  CodeFile,
  CodeProject,
  ProjectSummary,
  StaticCodeFinding,
  StaticDataFlow,
  StaticRoute,
} from "../src/types/resources";

vi.mock("@monaco-editor/react", () => ({
  default: ({ value }: { value?: string }) => (
    <pre data-testid="monaco-preview">{value}</pre>
  ),
}));

vi.mock("@xyflow/react", () => ({
  Background: () => null,
  Controls: () => null,
  Position: { Left: "left", Right: "right" },
  ReactFlow: ({
    nodes,
    "aria-label": ariaLabel,
  }: {
    nodes: Array<{ id: string; data: { label: string } }>;
    "aria-label"?: string;
  }) => (
    <div aria-label={ariaLabel}>
      {nodes.map((node) => <span key={node.id}>{node.data.label}</span>)}
    </div>
  ),
}));

const parentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const codeProjectId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const fileId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const routeId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const findingId = "ffffffff-ffff-4fff-8fff-ffffffffffff";

const parent: ProjectSummary = {
  id: parentId,
  name: "Authorized Challenge",
  description: "Source review scope",
  mode: "ctf",
  version: 1,
  workspace_count: 0,
  scope_rule_count: 0,
  created_at: "2026-08-09T00:00:00Z",
  updated_at: "2026-08-09T00:00:00Z",
};

const codeProject: CodeProject = {
  id: codeProjectId,
  project_id: parentId,
  name: "Flask Shop",
  description: "Inert source review",
  authorization_confirmed: true,
  authorization_notes: "Explicit CTF source review permission recorded.",
  status: "completed",
  languages: ["python"],
  frameworks: ["Flask"],
  dependency_files: ["requirements.txt"],
  warnings: [],
  total_files: 2,
  total_bytes: 420,
  secret_findings_count: 1,
  analyzed_at: "2026-08-09T00:02:00Z",
  created_at: "2026-08-09T00:00:00Z",
  updated_at: "2026-08-09T00:02:00Z",
};

const codeFile: CodeFile = {
  id: fileId,
  relative_path: "app.py",
  language: "python",
  size_bytes: 400,
  sha256: "a".repeat(64),
  secret_findings_count: 1,
  warning_codes: [],
  route_count: 1,
};

const route: StaticRoute = {
  id: routeId,
  code_file_id: fileId,
  framework: "Flask",
  methods: ["GET"],
  path: "/product/<int:item_id>",
  handler_name: "product",
  file_path: "app.py",
  line_start: 8,
  line_end: 11,
  parameters: [
    { name: "item_id", location: "path", required: true },
    { name: "q", location: "query", required: false },
  ],
  authentication: {
    required: true,
    mechanisms: ["login_required"],
    limitations: [],
  },
  findings: [findingId],
};

const staticFinding: StaticCodeFinding = {
  id: findingId,
  code_project_id: codeProjectId,
  code_file_id: fileId,
  static_route_id: routeId,
  file_path: "app.py",
  route: "/product/<int:item_id>",
  route_handler: "product",
  category: "sql_injection",
  title: "Potential SQL Injection",
  status: "static_candidate",
  severity: "high",
  confidence: 0.9,
  source_label: "request.query['q']",
  sink_label: "cursor.execute",
  parameter: "q",
  source_line: 9,
  sink_line: 11,
  sanitizers: [],
  evidence: ["Source observed at line 9.", "Sink receives the traced value at line 11."],
  remediation: {
    summary: "Keep user data separate from SQL syntax.",
    guidance: ["Use parameter binding."],
    safe_example: 'cursor.execute("SELECT * FROM items WHERE id = ?", (item_id,))',
    verification: "Confirm request data no longer reaches SQL text.",
  },
  limitations: ["Intra-procedural analysis does not prove runtime reachability."],
};

const staticFlow: StaticDataFlow = {
  finding_id: findingId,
  nodes: [
    { id: "step-0", kind: "source", label: "request.query['q']", line: 9, detail: "Input" },
    { id: "step-1", kind: "transformation", label: "f-string interpolation", line: 10, detail: "Compose" },
    { id: "step-2", kind: "sink", label: "cursor.execute", line: 11, detail: "SQL sink" },
  ],
  edges: [
    { id: "edge-0", source: "step-0", target: "step-1", label: "flows to" },
    { id: "edge-1", source: "step-1", target: "step-2", label: "flows to" },
  ],
};

const analysis: CodeAnalysis = {
  project: codeProject,
  routes: [route],
  analysis_log: ["No code executed"],
  limitations: ["Static candidates are not Runtime Confirmed."],
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

describe("Phase 10 inert code analysis", () => {
  it("renders redacted source and maps a static route to its file", async () => {
    window.history.pushState({}, "", "/code-analysis");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input);
      if (path === "/api/projects") return response([parent]);
      if (path === "/api/code-projects") return response([codeProject]);
      if (path === `/api/code-projects/${codeProjectId}/files`) return response([codeFile]);
      if (path === `/api/code-projects/${codeProjectId}/files/${fileId}`) {
        return response({
          ...codeFile,
          content: 'API_KEY = "<redacted-secret>"\n\ndef product():\n    pass',
          redacted: true,
          truncated: false,
        });
      }
      if (path === `/api/code-projects/${codeProjectId}/routes`) return response([route]);
      if (path === `/api/code-projects/${codeProjectId}/findings`) {
        return response([staticFinding]);
      }
      if (path === `/api/code-projects/${codeProjectId}/data-flows`) {
        return response([staticFlow]);
      }
      if (path === `/api/code-projects/${codeProjectId}/analysis`) return response(analysis);
      if (path === `/api/code-projects/${codeProjectId}/analyze` && init?.method === "POST") {
        return response(analysis);
      }
      return response({ message: `Unhandled ${path}` }, 404);
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    expect(await screen.findByRole("heading", { name: "Code Analysis" })).toBeInTheDocument();
    expect(await screen.findByText("app.py")).toBeInTheDocument();
    expect(await screen.findByText("Secrets masked")).toBeInTheDocument();
    expect(screen.getByTestId("monaco-preview")).toHaveTextContent("<redacted-secret>");
    expect(screen.getByText("Flask")).toBeInTheDocument();
    expect((await screen.findAllByText("Potential SQL Injection")).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: /Potential SQL Injection/ }));
    expect(screen.getByText("No supported sanitizer observed")).toBeInTheDocument();
    expect(screen.getByLabelText("Source-to-Sink data flow")).toHaveTextContent("cursor.execute");
    expect(screen.getByText("Safe remediation diff")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /GET.*product/ }));
    expect(await screen.findByText(/product · app.py:8/)).toBeInTheDocument();
    expect(screen.getByText("query:q")).toBeInTheDocument();
    expect(screen.getByText("Auth signal observed")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Analyze source flows" }));
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        `/api/code-projects/${codeProjectId}/analyze`,
        expect.objectContaining({ method: "POST" }),
      );
    });
  });

  it("creates a metadata project then uploads only after explicit authorization", async () => {
    window.history.pushState({}, "", "/code-analysis");
    let uploadedForm: FormData | undefined;
    const emptyProject: CodeProject = {
      ...codeProject,
      id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
      name: "New upload",
      status: "empty",
      total_files: 0,
      total_bytes: 0,
      secret_findings_count: 0,
      frameworks: [],
      languages: [],
      dependency_files: [],
      analyzed_at: null,
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = pathOf(input);
      if (path === "/api/projects") return response([parent]);
      if (path === "/api/code-projects" && init?.method === "POST") {
        if (typeof init.body !== "string") throw new Error("Expected JSON request body");
        const body = JSON.parse(init.body) as Record<string, unknown>;
        expect(body).toMatchObject({
          authorization_confirmed: true,
          authorization_notes: "Authorized source review without execution",
          confirmation_phrase: "UPLOAD INERT SOURCE",
        });
        return response(emptyProject, 201);
      }
      if (path === "/api/code-projects/upload" && init?.method === "POST") {
        uploadedForm = init.body as FormData;
        return response(
          {
            project: { ...emptyProject, status: "indexed", total_files: 1 },
            files: [codeFile],
            policy: {
              max_archive_bytes: 50_000_000,
              max_extracted_bytes: 200_000_000,
              max_files: 5_000,
              max_single_file_bytes: 5_000_000,
              max_archive_depth: 2,
            },
            execution_performed: false,
          },
          201,
        );
      }
      if (path === "/api/code-projects") return response([]);
      return response({ message: `Unhandled ${path}` }, 404);
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    const uploadButton = await screen.findByRole("button", { name: "Validate & index" });
    expect(uploadButton).toBeDisabled();
    await userEvent.upload(
      screen.getByLabelText("Source files"),
      new File(["from flask import Flask"], "app.py", { type: "text/x-python" }),
    );
    expect(uploadButton).toBeDisabled();
    await userEvent.click(screen.getByLabelText("Confirm source authorization"));
    await userEvent.click(uploadButton);
    await waitFor(() => expect(uploadedForm).toBeDefined());
    expect(uploadedForm?.get("code_project_id")).toBe(emptyProject.id);
    expect((uploadedForm?.get("files") as File).name).toBe("app.py");
  });
});

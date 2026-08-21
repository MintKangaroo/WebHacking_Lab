import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../src/app";
import type { DashboardOverview } from "../src/types/dashboard";
import type { LabCatalog } from "../src/types/resources";

const overview: DashboardOverview = {
  workspace_name: "Test Workspace",
  demo_mode: true,
  safety: {
    mode: "Analysis Only",
    network_execution_enabled: false,
    ctf_mode_enabled: false,
    insecure_tls_allowed: false,
    max_response_bytes: 2_097_152,
    global_requests_per_minute: 30,
  },
  metrics: [{ label: "Active projects", value: 3, delta: null, trend: "neutral" }],
  severity_distribution: [{ severity: "High", count: 2 }],
  request_volume: [{ label: "09:00", requests: 12, blocked: 1 }],
  analysis_types: [{ category: "Headers", count: 42 }],
  recent_activity: [],
};

const catalog: LabCatalog = {
  enabled: true,
  warning: "These targets are intentionally vulnerable.",
  labs: [
    {
      id: "sqli",
      name: "SQL Injection",
      category: "sql_injection",
      difficulty: "beginner",
      description: "desc",
      base_url: "http://lab-sqli:5000",
      target_path: "/products?id=1",
      objective: "obj",
      hint: "hint",
    },
  ],
};

function response(payload: unknown) {
  return new Response(JSON.stringify(payload), {
    status: 200,
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

describe("Dashboard local-labs widget", () => {
  it("summarizes the labs and links each to a pre-filled scan", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (path === "/api/dashboard/overview") return Promise.resolve(response(overview));
      if (path === "/api/labs") return Promise.resolve(response(catalog));
      return Promise.resolve(response({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByText("Local Labs")).toBeInTheDocument();
    expect(await screen.findByText("SQL Injection")).toBeInTheDocument();
    expect(screen.getByText("Running")).toBeInTheDocument();

    const scanLink = screen.getByRole("link", { name: "Scan" });
    const href = scanLink.getAttribute("href") ?? "";
    expect(href).toContain("/scans?");
    expect(href).toContain("labId=sqli");
    expect(href).toContain("profile=ctf");
  });
});

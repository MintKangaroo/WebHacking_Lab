import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/app";
import type { DashboardOverview } from "../src/types/dashboard";

const dashboardFixture: DashboardOverview = {
  workspace_name: "Test Workspace",
  demo_mode: true,
  safety: {
    mode: "Analysis Only",
    network_execution_enabled: false,
    insecure_tls_allowed: false,
    max_response_bytes: 2_097_152,
    global_requests_per_minute: 30,
  },
  metrics: [
    { label: "Active projects", value: 3, delta: 12, trend: "up" },
    { label: "Analyzed requests", value: 148, delta: 18, trend: "up" },
    { label: "Finding candidates", value: 12, delta: -4, trend: "down" },
    { label: "Confirmed findings", value: 4, delta: 2, trend: "up" },
    { label: "Scope blocks", value: 7, delta: null, trend: "neutral" },
  ],
  severity_distribution: [
    { severity: "Critical", count: 0 },
    { severity: "High", count: 2 },
    { severity: "Medium", count: 6 },
    { severity: "Low", count: 4 },
    { severity: "Info", count: 9 },
  ],
  request_volume: [{ label: "09:00", requests: 12, blocked: 1 }],
  analysis_types: [{ category: "Headers", count: 42 }],
  recent_activity: [
    {
      id: "test-activity",
      kind: "scope",
      title: "Out-of-scope target blocked",
      detail: "The host was not present in the project allowlist.",
      occurred_at: "now",
      status: "blocked",
    },
  ],
};

describe("Dashboard", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(dashboardFixture), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders API-backed safety and activity data", async () => {
    render(<App />);

    expect(
      await screen.findByRole("heading", {
        name: "Security analysis, under control.",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("Analyzed requests")).toBeInTheDocument();
    expect(screen.getByText("Out-of-scope target blocked")).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/dashboard/overview"),
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("opens and closes the keyboard command palette", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Analyzed requests");

    await user.keyboard("{Control>}k{/Control}");
    expect(
      screen.getByRole("dialog", { name: "Command palette" }),
    ).toBeInTheDocument();

    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: "Command palette" }),
      ).not.toBeInTheDocument();
    });
  });
});

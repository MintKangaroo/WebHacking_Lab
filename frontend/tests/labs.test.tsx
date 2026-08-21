import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../src/app";
import type { LabCatalog } from "../src/types/resources";

const catalog: LabCatalog = {
  enabled: false,
  warning: "These targets are intentionally vulnerable and run only on the isolated network.",
  labs: [
    {
      id: "sqli",
      name: "SQL Injection",
      category: "sql_injection",
      difficulty: "beginner",
      description: "A product lookup that concatenates the id parameter into a SQL query.",
      base_url: "http://lab-sqli:5000",
      target_path: "/products?id=1",
      objective: "Recover the flag from the secrets table via SQL injection.",
      hint: "Try id=0 UNION SELECT 1, flag, 3 FROM secrets.",
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

describe("Local labs page", () => {
  it("lists the vulnerable labs with their objective and target", async () => {
    window.history.pushState({}, "", "/labs");
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (path === "/api/labs") return Promise.resolve(response(catalog));
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByText("SQL Injection")).toBeInTheDocument();
    expect(
      screen.getByText(/Recover the flag from the secrets table/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/http:\/\/lab-sqli:5000/)).toBeInTheDocument();
    expect(screen.getByText(/Disabled by default/i)).toBeInTheDocument();
  });

  it("disables the scan action while labs are turned off", async () => {
    window.history.pushState({}, "", "/labs");
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (path === "/api/labs") return Promise.resolve(response(catalog));
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    const button = await screen.findByRole("button", { name: /Enable labs to scan/i });
    expect(button).toBeDisabled();
  });

  it("links the scan action to a pre-filled scan plan when labs are enabled", async () => {
    window.history.pushState({}, "", "/labs");
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = pathOf(input);
      if (path === "/api/labs") {
        return Promise.resolve(response({ ...catalog, enabled: true }));
      }
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    const link = await screen.findByRole("link", { name: /Scan this lab/i });
    const href = link.getAttribute("href") ?? "";
    expect(href).toContain("/scans?");
    expect(href).toContain("profile=ctf");
    expect(href).toContain("labId=sqli");
    expect(decodeURIComponent(href)).toContain("http://lab-sqli:5000/products?id=1");
    expect(href).toContain("scopeHost=lab-sqli");
    expect(href).toContain("scopePort=5000");
  });
});

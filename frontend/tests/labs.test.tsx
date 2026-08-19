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
});

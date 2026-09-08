import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../src/app";
import type { CtfChallenge } from "../src/types/resources";

const challenge: CtfChallenge = {
  id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  name: "Baby SQLi",
  event: "PicoCTF 2025",
  category: "web",
  difficulty: "easy",
  points: 100,
  target_url: "https://ctf.example/chal?id=1",
  status: "todo",
  notes: "UNION based",
  flag: "",
  solved_at: null,
  created_at: "2026-09-08T00:00:00Z",
  updated_at: "2026-09-08T00:00:00Z",
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

describe("CTF Workspace page", () => {
  it("lists challenges grouped by event with a scan shortcut", async () => {
    window.history.pushState({}, "", "/ctf");
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      if (pathOf(input) === "/api/ctf/challenges") return Promise.resolve(response([challenge]));
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByText("Baby SQLi")).toBeInTheDocument();
    expect(screen.getByText("PicoCTF 2025")).toBeInTheDocument();
    const scanLink = screen.getByRole("link", { name: "Scan" });
    expect(scanLink).toHaveAttribute(
      "href",
      "/scans?target=https%3A%2F%2Fctf.example%2Fchal%3Fid%3D1&profile=ctf",
    );
  });

  it("creates a challenge through the form", async () => {
    window.history.pushState({}, "", "/ctf");
    const posted: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (pathOf(input) === "/api/ctf/challenges" && init?.method === "POST") {
        posted.push(JSON.parse(init.body as string));
        return Promise.resolve(response({ ...challenge, name: "New chal" }, 201));
      }
      if (pathOf(input) === "/api/ctf/challenges") return Promise.resolve(response([]));
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: /new challenge/i }));
    await userEvent.type(screen.getByLabelText("Name"), "New chal");
    await userEvent.click(screen.getByRole("button", { name: /add challenge/i }));

    await waitFor(() => expect(posted).toHaveLength(1));
    expect((posted[0] as { name: string }).name).toBe("New chal");
  });

  it("cycles status by clicking the status badge", async () => {
    window.history.pushState({}, "", "/ctf");
    const patched: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === "PATCH") {
        patched.push(JSON.parse(init.body as string));
        return Promise.resolve(response({ ...challenge, status: "in_progress" }));
      }
      if (pathOf(input) === "/api/ctf/challenges") return Promise.resolve(response([challenge]));
      return Promise.resolve(response({ message: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: /cycle status for Baby SQLi/i }));
    await waitFor(() => expect(patched).toHaveLength(1));
    expect((patched[0] as { status: string }).status).toBe("in_progress");
  });
});

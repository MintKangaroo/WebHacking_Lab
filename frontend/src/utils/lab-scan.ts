import type { LabInfo } from "../types/resources";

/**
 * Build the `/scans` query string that pre-fills a scan plan for a lab:
 * target URL, CTF profile, and the lab host carried as scope hints. The
 * scanner reads these on mount (see ScansPage).
 */
export function buildLabScanSearch(lab: LabInfo): string {
  const url = new URL(lab.base_url);
  const params = new URLSearchParams({
    labId: lab.id,
    target: `${lab.base_url}${lab.target_path}`,
    profile: "ctf",
    scopeScheme: url.protocol.replace(":", ""),
    scopeHost: url.hostname,
  });
  if (url.port) params.set("scopePort", url.port);
  return `?${params.toString()}`;
}

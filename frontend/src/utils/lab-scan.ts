import type { LabInfo } from "../types/resources";

/**
 * Build the `/scans` query string that pre-fills a scan plan for a lab:
 * target URL, LOCAL_LAB profile, and the lab host carried as scope hints. The
 * scanner reads these on mount (see ScansPage). LOCAL_LAB is the narrow
 * relaxation scoped to the built-in labs — it does not require the broad CTF
 * "scan anything" mode.
 */
export function buildLabScanSearch(lab: LabInfo): string {
  const url = new URL(lab.base_url);
  const params = new URLSearchParams({
    labId: lab.id,
    target: `${lab.base_url}${lab.target_path}`,
    profile: "local_lab",
    scopeScheme: url.protocol.replace(":", ""),
    scopeHost: url.hostname,
  });
  if (url.port) params.set("scopePort", url.port);
  return `?${params.toString()}`;
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  CircleStop,
  Clock3,
  ExternalLink,
  Fingerprint,
  FlaskConical,
  Gauge,
  Globe2,
  ListTree,
  Radar,
  ShieldAlert,
  ShieldCheck,
  SquareMousePointer,
} from "lucide-react";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { toast } from "sonner";

import { dashboardQueryOptions } from "../api/dashboard";
import {
  checkScope,
  createScope,
  getProject,
  getProjects,
} from "../api/projects";
import {
  approveScanTests,
  cancelScan,
  createScan,
  getScan,
  getScanEndpoints,
  getScanEvents,
  getScanFindings,
  getScanParameters,
  getScans,
  getScanTests,
} from "../api/scans";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import type { ScannerProfile, ScanJob, ScanStatus } from "../types/resources";
import { cn } from "../utils/cn";

const fieldClass =
  "h-10 w-full rounded-md border border-line bg-black/20 px-3 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-400/50";
const terminalStatuses = new Set<ScanStatus>([
  "completed",
  "cancelled",
  "failed",
  "blocked",
]);

function statusTone(status: ScanStatus): "safe" | "warning" | "critical" | "accent" {
  if (status === "completed") return "safe";
  if (status === "failed" || status === "blocked") return "critical";
  if (status === "cancelled" || status === "waiting_for_approval") return "warning";
  return "accent";
}

function compactTarget(target: string) {
  try {
    const url = new URL(target);
    return `${url.host}${url.pathname}`;
  } catch {
    return target;
  }
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-line bg-black/15 px-3 py-2.5">
      <p className="font-mono text-base text-slate-100">{value}</p>
      <p className="mt-0.5 text-[10px] uppercase tracking-wider text-slate-600">{label}</p>
    </div>
  );
}

function ScanList({
  scans,
  selectedId,
  onSelect,
}: {
  scans: ScanJob[];
  selectedId?: string;
  onSelect: (id: string) => void;
}) {
  if (!scans.length) {
    return (
      <div className="py-10 text-center">
        <Radar className="mx-auto size-7 text-slate-700" />
        <p className="mt-3 text-sm text-slate-400">No scan jobs yet</p>
        <p className="mt-1 text-xs text-slate-600">Start a passive scan or a separately approved SAFE plan.</p>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {scans.map((scan) => (
        <button
          key={scan.id}
          type="button"
          onClick={() => onSelect(scan.id)}
          className={cn(
            "w-full rounded-lg border p-3 text-left transition-colors",
            selectedId === scan.id
              ? "border-cyan-400/30 bg-cyan-400/[0.06]"
              : "border-line bg-black/10 hover:bg-white/[0.025]",
          )}
        >
          <div className="flex items-center justify-between gap-3">
            <span className="truncate font-mono text-xs text-slate-300">
              {compactTarget(scan.target)}
            </span>
            <Badge tone={statusTone(scan.status)}>{scan.status.replaceAll("_", " ")}</Badge>
          </div>
          <div className="mt-2 flex items-center gap-3 text-[11px] text-slate-600">
            <span>{scan.endpoints_count} endpoints</span>
            <span>{scan.requests_used}/{scan.request_budget} requests</span>
          </div>
        </button>
      ))}
    </div>
  );
}

type LabContext = {
  labId: string;
  scopeScheme: "http" | "https";
  scopeHost: string;
  scopePort: number | null;
};

type LabPrefill = {
  target: string;
  profile: Extract<ScannerProfile, "passive" | "safe" | "ctf">;
  expectedUse: string;
  context: LabContext;
};

/** Read a lab pre-fill from the `/scans` query string, or null when absent. */
function parseLabPrefill(searchParams: URLSearchParams): LabPrefill | null {
  const labId = searchParams.get("labId");
  const target = searchParams.get("target");
  if (!labId || !target) return null;
  const profile = searchParams.get("profile");
  return {
    target,
    profile: profile === "safe" || profile === "ctf" ? profile : "ctf",
    expectedUse: `Isolated local lab exercise: ${labId}`,
    context: {
      labId,
      scopeScheme: searchParams.get("scopeScheme") === "https" ? "https" : "http",
      scopeHost: searchParams.get("scopeHost") ?? "",
      scopePort: searchParams.get("scopePort")
        ? Number(searchParams.get("scopePort"))
        : null,
    },
  };
}

export function ScansPage() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  // Parse the lab pre-fill exactly once (lazy initializer) so later edits and
  // the URL cleanup below never re-seed the form.
  const [seeded] = useState<LabPrefill | null>(() =>
    searchParams.has("labId") ? parseLabPrefill(searchParams) : null,
  );

  const [projectId, setProjectId] = useState("");
  const [workspaceId, setWorkspaceId] = useState("");
  const [target, setTarget] = useState(seeded?.target ?? "http://127.0.0.1:8001/");
  const [profile, setProfile] = useState<Extract<ScannerProfile, "passive" | "safe" | "ctf">>(
    seeded?.profile ?? "passive",
  );
  const [expectedUse, setExpectedUse] = useState(
    seeded?.expectedUse ?? "Authorized application inventory and safe validation",
  );
  const [confirmed, setConfirmed] = useState(false);
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxPages, setMaxPages] = useState(20);
  const [maxRequests, setMaxRequests] = useState(30);
  const [requestsPerSecond, setRequestsPerSecond] = useState(1);
  const [maxActiveTests, setMaxActiveTests] = useState(6);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [selectedTestIds, setSelectedTestIds] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<"endpoints" | "parameters" | "tests" | "findings" | "events">("endpoints");
  const labContext = seeded?.context ?? null;

  // Drop the query string once the pre-fill is applied (navigation only, no
  // form state is touched here).
  useEffect(() => {
    if (seeded && searchParams.has("labId")) {
      setSearchParams({}, { replace: true });
    }
  }, [seeded, searchParams, setSearchParams]);

  const overview = useQuery(dashboardQueryOptions());
  const ctfModeEnabled = overview.data?.safety.ctf_mode_enabled ?? false;
  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: ({ signal }) => getProjects(signal),
  });
  const effectiveProjectId = projectId || projects.data?.[0]?.id || "";
  const project = useQuery({
    queryKey: ["project", effectiveProjectId],
    queryFn: ({ signal }) => getProject(effectiveProjectId, signal),
    enabled: Boolean(effectiveProjectId),
  });
  const enabledWorkspaces = project.data?.workspaces.filter(
    (workspace) => workspace.network_execution_enabled,
  ) ?? [];
  const effectiveWorkspaceId =
    enabledWorkspaces.find((workspace) => workspace.id === workspaceId)?.id ??
    enabledWorkspaces[0]?.id ??
    "";

  const trimmedTarget = target.trim();
  const scopeStatus = useQuery({
    queryKey: ["scope-check", effectiveProjectId, trimmedTarget],
    queryFn: () => checkScope(effectiveProjectId, trimmedTarget),
    enabled: Boolean(labContext && effectiveProjectId && trimmedTarget),
  });
  const addScope = useMutation({
    mutationFn: () => {
      if (!labContext) throw new Error("No lab target to register");
      return createScope(effectiveProjectId, {
        scheme: labContext.scopeScheme,
        hostname: labContext.scopeHost,
        port: labContext.scopePort,
        path_prefix: "/",
        allow_subdomains: false,
        authorization_confirmed: true,
        authorization_notes: `Isolated local lab: ${labContext.labId}`,
      });
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["project", effectiveProjectId] }),
        queryClient.invalidateQueries({
          queryKey: ["scope-check", effectiveProjectId, trimmedTarget],
        }),
      ]);
      toast.success("Lab host added to project scope");
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const scans = useQuery({
    queryKey: ["scans", effectiveProjectId],
    queryFn: ({ signal }) => getScans(effectiveProjectId || undefined, signal),
    refetchInterval: (query) => {
      const jobs = query.state.data;
      return jobs?.some((job) => !terminalStatuses.has(job.status)) ? 1500 : false;
    },
  });
  const effectiveScanId = selectedScanId || scans.data?.[0]?.id || "";
  const scan = useQuery({
    queryKey: ["scan", effectiveScanId],
    queryFn: ({ signal }) => getScan(effectiveScanId, signal),
    enabled: Boolean(effectiveScanId),
    refetchInterval: (query) => {
      const job = query.state.data;
      return job && !terminalStatuses.has(job.status) ? 1000 : false;
    },
  });
  const inventoryRefresh = scan.data && !terminalStatuses.has(scan.data.status) ? 1500 : false;
  const endpoints = useQuery({
    queryKey: ["scan-endpoints", effectiveScanId],
    queryFn: ({ signal }) => getScanEndpoints(effectiveScanId, signal),
    enabled: Boolean(effectiveScanId),
    refetchInterval: inventoryRefresh,
  });
  const parameters = useQuery({
    queryKey: ["scan-parameters", effectiveScanId],
    queryFn: ({ signal }) => getScanParameters(effectiveScanId, signal),
    enabled: Boolean(effectiveScanId),
    refetchInterval: inventoryRefresh,
  });
  const findings = useQuery({
    queryKey: ["scan-findings", effectiveScanId],
    queryFn: ({ signal }) => getScanFindings(effectiveScanId, signal),
    enabled: Boolean(effectiveScanId),
    refetchInterval: inventoryRefresh,
  });
  const events = useQuery({
    queryKey: ["scan-events", effectiveScanId],
    queryFn: ({ signal }) => getScanEvents(effectiveScanId, signal),
    enabled: Boolean(effectiveScanId),
    refetchInterval: inventoryRefresh,
  });
  const tests = useQuery({
    queryKey: ["scan-tests", effectiveScanId],
    queryFn: ({ signal }) => getScanTests(effectiveScanId, signal),
    enabled: Boolean(effectiveScanId),
    refetchInterval: inventoryRefresh,
  });

  const create = useMutation({
    mutationFn: createScan,
    onSuccess: async (job) => {
      setSelectedScanId(job.id);
      setConfirmed(false);
      await queryClient.invalidateQueries({ queryKey: ["scans", job.project_id] });
      toast.success(
        job.profile === "safe"
          ? "SAFE scan queued"
          : job.profile === "ctf"
            ? "CTF scan queued"
            : "Passive scan queued",
      );
    },
    onError: (error: Error) => toast.error(error.message),
  });
  const cancel = useMutation({
    mutationFn: cancelScan,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["scan", effectiveScanId] });
      toast.info("Cancellation requested");
    },
    onError: (error: Error) => toast.error(error.message),
  });
  const approve = useMutation({
    mutationFn: () => approveScanTests(effectiveScanId, selectedTestIds),
    onSuccess: async () => {
      setSelectedTestIds([]);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["scan", effectiveScanId] }),
        queryClient.invalidateQueries({ queryKey: ["scan-tests", effectiveScanId] }),
      ]);
      toast.success("Selected exact requests approved");
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const selectedWorkspace = enabledWorkspaces.find(
    (workspace) => workspace.id === effectiveWorkspaceId,
  );
  const usesActiveTests = profile === "safe" || profile === "ctf";
  const requestCeiling = Math.min(
    maxRequests + (usesActiveTests ? maxActiveTests : 0),
    selectedWorkspace
      ? selectedWorkspace.request_budget - selectedWorkspace.requests_used
      : maxRequests + (usesActiveTests ? maxActiveTests : 0),
  );
  const canSubmit = Boolean(
    effectiveProjectId &&
      effectiveWorkspaceId &&
      target.trim() &&
      expectedUse.trim().length >= 10 &&
      confirmed &&
      maxRequests >= maxPages,
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;
    create.mutate({
      project_id: effectiveProjectId,
      workspace_id: effectiveWorkspaceId,
      target: target.trim(),
      profile,
      crawl_policy: {
        max_depth: maxDepth,
        max_pages: maxPages,
        max_requests: maxRequests,
        max_response_bytes: 2_000_000,
        requests_per_second: requestsPerSecond,
        concurrency: 1,
        include_subdomains: false,
        respect_logout_routes: true,
        execute_javascript: false,
      },
      active_test_policy: {
        enabled: usesActiveTests,
        max_tests: maxActiveTests,
        max_tests_per_parameter: 6,
        allow_limited_timing: false,
      },
      authorization_confirmed: true,
      confirmation_phrase:
        profile === "safe"
          ? "START SAFE SCAN"
          : profile === "ctf"
            ? "START CTF SCAN"
            : "START PASSIVE SCAN",
      expected_use: expectedUse.trim(),
    });
  };

  const tabCounts = useMemo(
    () => ({
      endpoints: endpoints.data?.length ?? 0,
      parameters: parameters.data?.length ?? 0,
      tests: tests.data?.length ?? 0,
      findings: findings.data?.length ?? 0,
      events: events.data?.length ?? 0,
    }),
    [endpoints.data, parameters.data, tests.data, findings.data, events.data],
  );

  return (
    <div className="mx-auto max-w-[1600px] space-y-6 p-4 sm:p-6 lg:p-8">
      <header className="flex flex-col justify-between gap-4 xl:flex-row xl:items-end">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-cyan-400">
            Guarded URL discovery
          </p>
          <h1 className="mt-2 text-2xl font-semibold text-slate-50">Guarded URL Scanner</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">
            Inventory an authorized application passively, or let SAFE mode prepare a few inert,
            read-only tests. SAFE requests remain Preview-only until you select and approve their
            exact HTTP text.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge tone="safe"><ShieldCheck className="size-3" /> External hosts allowed only in registered scope</Badge>
          <Badge><SquareMousePointer className="size-3" /> Per-test approval</Badge>
        </div>
      </header>

      <div className="grid gap-6 2xl:grid-cols-[370px_minmax(0,1fr)]">
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Radar className="size-4 text-cyan-400" /> New scan plan</CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={submit} className="space-y-4">
                <label className="block text-xs text-slate-400">
                  Scan profile
                  <select
                    aria-label="Scan profile"
                    value={profile}
                    onChange={(event) =>
                      setProfile(event.target.value as "passive" | "safe" | "ctf")
                    }
                    className={`${fieldClass} mt-1.5`}
                  >
                    <option value="passive">PASSIVE · inventory only</option>
                    <option value="safe">SAFE · plan then approve tests</option>
                    {(ctfModeEnabled || profile === "ctf") && (
                      <option value="ctf">CTF · auto-run read-only probes</option>
                    )}
                  </select>
                </label>
                <label className="block text-xs text-slate-400">
                  Project
                  <select
                    aria-label="Project"
                    value={effectiveProjectId}
                    onChange={(event) => {
                      setProjectId(event.target.value);
                      setWorkspaceId("");
                      setSelectedScanId("");
                    }}
                    className={`${fieldClass} mt-1.5`}
                  >
                    {(projects.data ?? []).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
                  </select>
                </label>
                <label className="block text-xs text-slate-400">
                  Execution-enabled workspace
                  <select
                    aria-label="Execution-enabled workspace"
                    value={effectiveWorkspaceId}
                    onChange={(event) => setWorkspaceId(event.target.value)}
                    className={`${fieldClass} mt-1.5`}
                  >
                    {enabledWorkspaces.map((workspace) => <option key={workspace.id} value={workspace.id}>{workspace.name}</option>)}
                  </select>
                </label>
                {!project.isLoading && project.data && enabledWorkspaces.length === 0 && (
                  <div className="rounded-md border border-amber-400/20 bg-amber-400/[0.05] p-3 text-xs leading-5 text-amber-200/75">
                    This project has no execution-enabled workspace. Review its scope and enable
                    controlled requests first. <Link className="text-amber-200 underline" to={`/projects/${project.data.id}`}>Open project</Link>
                  </div>
                )}
                <label className="block text-xs text-slate-400">
                  Starting URL
                  <input aria-label="Starting URL" required value={target} onChange={(event) => setTarget(event.target.value)} className={`${fieldClass} mt-1.5 font-mono`} />
                </label>
                {labContext && (
                  <div className="space-y-2 rounded-lg border border-cyan-400/20 bg-cyan-400/[0.04] p-3">
                    <p className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-cyan-300">
                      <FlaskConical className="size-3.5" /> Lab target · {labContext.labId}
                    </p>
                    {scopeStatus.data?.allowed ? (
                      <p className="flex items-center gap-2 text-xs text-emerald-300">
                        <CheckCircle2 className="size-3.5" /> This lab host is in the selected project scope.
                      </p>
                    ) : (
                      <div className="space-y-2">
                        <p className="text-xs leading-5 text-slate-400">
                          {labContext.scopeScheme}://{labContext.scopeHost}
                          {labContext.scopePort ? `:${labContext.scopePort}` : ""} is not in this
                          project&apos;s scope yet. Add it to authorize the scan.
                        </p>
                        <Button
                          type="button"
                          size="sm"
                          variant="secondary"
                          disabled={!effectiveProjectId || addScope.isPending}
                          onClick={() => addScope.mutate()}
                        >
                          {addScope.isPending ? "Adding…" : "Add lab host to scope"}
                        </Button>
                      </div>
                    )}
                    {profile === "ctf" && !ctfModeEnabled && (
                      <p className="flex items-start gap-2 text-xs leading-5 text-amber-200/80">
                        <ShieldAlert className="mt-0.5 size-3.5 shrink-0" /> CTF probing is disabled on
                        this backend. Set WEBHACKING_CTF_MODE_ENABLED=true to auto-run lab probes.
                      </p>
                    )}
                  </div>
                )}
                <label className="block text-xs text-slate-400">
                  Authorized purpose
                  <textarea
                    aria-label="Authorized purpose"
                    required
                    minLength={10}
                    value={expectedUse}
                    onChange={(event) => setExpectedUse(event.target.value)}
                    className="mt-1.5 min-h-20 w-full resize-y rounded-md border border-line bg-black/20 p-3 text-sm text-slate-100 outline-none focus:border-cyan-400/50"
                  />
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <label className="text-xs text-slate-400">Depth<input aria-label="Maximum depth" type="number" min={0} max={5} value={maxDepth} onChange={(event) => setMaxDepth(event.currentTarget.valueAsNumber)} className={`${fieldClass} mt-1.5`} /></label>
                  <label className="text-xs text-slate-400">Pages<input aria-label="Maximum pages" type="number" min={1} max={100} value={maxPages} onChange={(event) => setMaxPages(event.currentTarget.valueAsNumber)} className={`${fieldClass} mt-1.5`} /></label>
                  <label className="text-xs text-slate-400">Requests<input aria-label="Maximum requests" type="number" min={1} max={300} value={maxRequests} onChange={(event) => setMaxRequests(event.currentTarget.valueAsNumber)} className={`${fieldClass} mt-1.5`} /></label>
                  <label className="text-xs text-slate-400">Req / sec<input aria-label="Requests per second" type="number" min={0.1} max={5} step={0.1} value={requestsPerSecond} onChange={(event) => setRequestsPerSecond(event.currentTarget.valueAsNumber)} className={`${fieldClass} mt-1.5`} /></label>
                </div>
                {usesActiveTests && (
                  <label className="block text-xs text-slate-400">
                    Maximum active tests
                    <input aria-label="Maximum active tests" type="number" min={1} max={10} value={maxActiveTests} onChange={(event) => setMaxActiveTests(event.currentTarget.valueAsNumber)} className={`${fieldClass} mt-1.5`} />
                  </label>
                )}
                {maxRequests < maxPages && <p className="text-xs text-red-300">Request limit must be at least the page limit.</p>}
                <div className="rounded-lg border border-cyan-400/15 bg-cyan-400/[0.035] p-3">
                  <p className="text-[10px] font-medium uppercase tracking-wider text-cyan-300">Exact safety envelope</p>
                  <ul className="mt-2 space-y-1 text-xs leading-5 text-slate-400">
                    <li>Up to {requestCeiling} total requests, sequentially</li>
                    <li>Scope or global rate limits may reduce the selected speed</li>
                    <li>Maximum 2 MB response per request</li>
                    <li>Logout-like routes skipped; JavaScript disabled</li>
                    <li>Redirect target fully revalidated before use</li>
                    {profile === "safe" && <li>{maxActiveTests} low-risk tests maximum; none run before separate approval</li>}
                    {profile === "ctf" && <li>{maxActiveTests} read-only probes maximum; auto-approved and run unattended on the authorized target</li>}
                  </ul>
                </div>
                <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-line p-3 text-xs leading-5 text-slate-400">
                  <input
                    aria-label="Confirm authorization"
                    type="checkbox"
                    checked={confirmed}
                    onChange={(event) => setConfirmed(event.target.checked)}
                    className="mt-1 accent-cyan-400"
                  />
                  <span>I own this target or have explicit permission to perform this bounded {profile.toUpperCase()} scan.</span>
                </label>
                <Button type="submit" className="w-full" disabled={!canSubmit || create.isPending}>
                  {create.isPending ? "Validating scope…" : `Start ${profile.toUpperCase()} scan`}
                </Button>
              </form>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Recent jobs</CardTitle></CardHeader>
            <CardContent><ScanList scans={scans.data ?? []} selectedId={effectiveScanId} onSelect={(id) => { setSelectedScanId(id); setSelectedTestIds([]); }} /></CardContent>
          </Card>
        </div>

        <div className="min-w-0 space-y-6">
          {scan.data ? (
            <>
              <Card className="overflow-hidden">
                <div className="h-1 bg-black/30"><div className="h-full bg-cyan-400 transition-[width]" style={{ width: `${Math.round(scan.data.progress * 100)}%` }} /></div>
                <CardContent className="p-5">
                  <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone={statusTone(scan.data.status)}>{scan.data.status.replaceAll("_", " ")}</Badge>
                        <span className="font-mono text-[11px] text-slate-600">{scan.data.id.slice(0, 8)}</span>
                      </div>
                      <p className="mt-3 truncate font-mono text-sm text-slate-200">{scan.data.target}</p>
                      <p className="mt-1 text-xs text-slate-500">{scan.data.current_stage} · {Math.round(scan.data.progress * 100)}%</p>
                    </div>
                    {!terminalStatuses.has(scan.data.status) && (
                      <Button variant="secondary" size="sm" onClick={() => cancel.mutate(scan.data.id)} disabled={cancel.isPending || scan.data.cancellation_requested}>
                        <CircleStop className="size-3.5" /> {scan.data.cancellation_requested ? "Stopping…" : "Stop scan"}
                      </Button>
                    )}
                  </div>
                  <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
                    <Stat label="Endpoints" value={scan.data.endpoints_count} />
                    <Stat label="Parameters" value={scan.data.parameters_count} />
                    <Stat label="Candidates" value={scan.data.findings_count} />
                    <Stat label="Request budget" value={`${scan.data.requests_used}/${scan.data.request_budget}`} />
                  </div>
                  {scan.data.error_message && <p className="mt-4 rounded-md border border-red-400/20 bg-red-400/[0.05] p-3 text-xs text-red-300">{scan.data.error_message}</p>}
                </CardContent>
              </Card>

              {scan.data.status === "waiting_for_approval" && (
                <Card className="border-amber-400/20 bg-amber-400/[0.035]">
                  <CardContent className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center">
                    <ShieldAlert className="size-5 shrink-0 text-amber-300" />
                    <div className="flex-1">
                      <p className="text-sm font-medium text-amber-100">No SAFE test has been sent</p>
                      <p className="mt-1 text-xs leading-5 text-amber-200/60">Review the exact HTTP previews, select only the tests you accept, then approve them once.</p>
                    </div>
                    <Button variant="secondary" size="sm" onClick={() => setActiveTab("tests")}>Review {scan.data.planned_tests_count} previews</Button>
                  </CardContent>
                </Card>
              )}

              <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_300px]">
                <Card className="min-w-0 overflow-hidden">
                  <div className="flex overflow-x-auto border-b border-line px-2">
                    {(["endpoints", "parameters", "tests", "findings", "events"] as const).map((tab) => (
                      <button key={tab} type="button" onClick={() => setActiveTab(tab)} className={cn("border-b-2 px-4 py-3 text-xs capitalize", activeTab === tab ? "border-cyan-400 text-cyan-300" : "border-transparent text-slate-500 hover:text-slate-300")}>
                        {tab} <span className="ml-1 font-mono text-[10px] text-slate-600">{tabCounts[tab]}</span>
                      </button>
                    ))}
                  </div>
                  <CardContent className="max-h-[620px] overflow-auto p-0">
                    {activeTab === "endpoints" && (
                      <div className="divide-y divide-line/70">
                        {(endpoints.data ?? []).map((item) => (
                          <div key={item.id} className="flex items-start gap-3 p-4">
                            <Badge tone={item.fetched ? "safe" : "neutral"}>{item.method}</Badge>
                            <div className="min-w-0 flex-1"><p className="break-all font-mono text-xs text-slate-300">{item.url}</p><p className="mt-1 text-[11px] text-slate-600">{item.source} · depth {item.depth}{item.status_code ? ` · HTTP ${item.status_code}` : ""}</p></div>
                            {item.fetched && <CheckCircle2 className="size-4 shrink-0 text-emerald-400" />}
                          </div>
                        ))}
                        {!endpoints.data?.length && <p className="p-10 text-center text-sm text-slate-600">No endpoints recorded yet.</p>}
                      </div>
                    )}
                    {activeTab === "parameters" && (
                      <div className="divide-y divide-line/70">
                        {(parameters.data ?? []).map((item) => (
                          <div key={item.id} className="grid gap-2 p-4 sm:grid-cols-[90px_150px_minmax(0,1fr)]">
                            <Badge>{item.location}</Badge><code className="text-xs text-violet-300">{item.name}</code><p className="truncate font-mono text-[11px] text-slate-600">{item.endpoint_url}</p>
                          </div>
                        ))}
                        {!parameters.data?.length && <p className="p-10 text-center text-sm text-slate-600">No parameters recorded yet.</p>}
                      </div>
                    )}
                    {activeTab === "findings" && (
                      <div className="space-y-3 p-4">
                        {(findings.data ?? []).map((item) => (
                          <div key={item.id} className="rounded-lg border border-line bg-black/15 p-4">
                            <div className="flex flex-wrap items-center gap-2"><Badge tone={item.severity === "high" || item.severity === "critical" ? "critical" : item.severity === "medium" ? "warning" : "accent"}>{item.severity}</Badge><Badge>{item.status}</Badge><span className="font-mono text-[11px] text-slate-600">{Math.round(item.confidence * 100)}%</span></div>
                            <h3 className="mt-3 text-sm font-medium text-slate-100">{item.title}</h3><p className="mt-1 text-xs leading-5 text-slate-500">{item.summary}</p><p className="mt-2 truncate font-mono text-[10px] text-slate-700">{item.endpoint_url}</p>
                          </div>
                        ))}
                        {!findings.data?.length && <p className="p-8 text-center text-sm text-slate-600">No passive candidates recorded.</p>}
                      </div>
                    )}
                    {activeTab === "tests" && (
                      <div className="space-y-3 p-4">
                        {(tests.data ?? []).map((item) => {
                          const selectable = scan.data.status === "waiting_for_approval" && item.status === "preview";
                          const checked = selectedTestIds.includes(item.id);
                          return (
                            <label key={item.id} className={cn("block rounded-lg border p-4", checked ? "border-cyan-400/30 bg-cyan-400/[0.04]" : "border-line bg-black/15", selectable && "cursor-pointer")}>
                              <div className="flex items-start gap-3">
                                <input aria-label={`Select ${item.title}`} type="checkbox" checked={checked} disabled={!selectable} onChange={() => setSelectedTestIds((current) => current.includes(item.id) ? current.filter((id) => id !== item.id) : [...current, item.id])} className="mt-1 accent-cyan-400" />
                                <div className="min-w-0 flex-1">
                                  <div className="flex flex-wrap items-center gap-2"><Badge tone={item.status === "completed" ? "safe" : item.status === "blocked" ? "critical" : item.status === "preview" ? "warning" : "accent"}>{item.status}</Badge><Badge>{item.risk_level} risk</Badge><span className="font-mono text-[10px] text-slate-600">1 request</span></div>
                                  <h3 className="mt-2 text-sm font-medium text-slate-100">{item.title}</h3>
                                  <p className="mt-1 text-xs leading-5 text-slate-500">{item.objective}</p>
                                  <pre className="mt-3 overflow-x-auto rounded-md border border-line bg-black/30 p-3 font-mono text-[11px] leading-5 text-slate-300">{item.exact_request_preview}</pre>
                                  <div className="mt-3 grid gap-3 text-[11px] leading-4 text-slate-600 sm:grid-cols-2"><p><span className="text-slate-400">Success:</span> {item.success_criteria}</p><p><span className="text-slate-400">False positive:</span> {item.false_positive_notes}</p></div>
                                  {item.result_status && <p className="mt-3 text-xs text-emerald-300">Result: {item.result_status} · {Math.round((item.confidence ?? 0) * 100)}% confidence</p>}
                                  {item.error_message && <p className="mt-3 text-xs text-red-300">{item.error_message}</p>}
                                </div>
                              </div>
                            </label>
                          );
                        })}
                        {!tests.data?.length && <p className="p-8 text-center text-sm text-slate-600">Passive scans have no active test previews.</p>}
                        {scan.data.status === "waiting_for_approval" && Boolean(tests.data?.length) && (
                          <div className="sticky bottom-0 flex flex-col gap-3 rounded-lg border border-cyan-400/20 bg-[#111a25]/95 p-4 shadow-xl backdrop-blur sm:flex-row sm:items-center">
                            <p className="flex-1 text-xs leading-5 text-slate-400">Selected {selectedTestIds.length}. Approval sends only these exact single requests; unselected previews remain unsent.</p>
                            <Button disabled={!selectedTestIds.length || approve.isPending} onClick={() => approve.mutate()}>{approve.isPending ? "Approving…" : "Approve selected tests"}</Button>
                          </div>
                        )}
                      </div>
                    )}
                    {activeTab === "events" && (
                      <div className="divide-y divide-line/70">
                        {(events.data ?? []).map((item) => (
                          <div key={item.id} className="flex gap-3 p-4"><Clock3 className="mt-0.5 size-3.5 shrink-0 text-slate-600" /><div><p className="text-xs text-slate-300">{item.message}</p><p className="mt-1 text-[10px] uppercase tracking-wider text-slate-600">{item.stage} · {new Date(item.created_at).toLocaleTimeString()}</p></div></div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>

                <div className="space-y-6">
                  <Card>
                    <CardHeader><CardTitle className="flex items-center gap-2"><Fingerprint className="size-4 text-violet-300" /> Technology signals</CardTitle></CardHeader>
                    <CardContent className="space-y-3">
                      {scan.data.fingerprints.map((item) => (
                        <div key={`${item.name}-${item.evidence}`} className="rounded-lg border border-line bg-black/10 p-3"><div className="flex justify-between gap-2"><span className="text-xs font-medium text-slate-200">{item.name}</span><span className="font-mono text-[10px] text-violet-300">{Math.round(item.confidence * 100)}%</span></div><p className="mt-1.5 text-[11px] leading-4 text-slate-600">{item.evidence}</p></div>
                      ))}
                      {!scan.data.fingerprints.length && <p className="text-xs text-slate-600">Fingerprint signals appear after responses are analyzed.</p>}
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle className="flex items-center gap-2"><ShieldAlert className="size-4 text-amber-300" /> Enforced boundaries</CardTitle></CardHeader>
                    <CardContent className="space-y-2 text-xs leading-5 text-slate-500">
                      <p>GET-only crawl; SAFE adds single GET/OPTIONS tests</p><p>One request per approved test</p><p>No browser JavaScript</p><p>No extraction, delay, write, or command payloads</p><p>Secret-shaped parameters skipped and masked</p>
                      <a href="/api/docs#/scanner" target="_blank" rel="noreferrer" className="mt-3 inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200">Scanner API <ExternalLink className="size-3" /></a>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </>
          ) : (
            <Card><CardContent className="grid min-h-[520px] place-items-center text-center"><div><Globe2 className="mx-auto size-10 text-slate-700" /><h2 className="mt-4 text-base font-medium text-slate-300">Select or create a scan</h2><p className="mt-2 max-w-sm text-sm leading-6 text-slate-600">Endpoint inventory, passive findings, policy events, and request usage will appear here in real time.</p></div></CardContent></Card>
          )}
        </div>
      </div>

      <Card className="border-violet-400/10 bg-violet-400/[0.02]">
        <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
          <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-violet-400/10"><ListTree className="size-4 text-violet-300" /></div>
          <div><p className="text-xs font-medium text-slate-300">SAFE mode stops for a second approval.</p><p className="mt-1 text-xs text-slate-600">SQL error/boolean signals, inert reflection, reserved-domain redirect, and CORS policy checks are bounded. Limited timing and data extraction remain disabled.</p></div>
          <Badge className="sm:ml-auto"><Gauge className="size-3" /> Max 10 tests</Badge>
        </CardContent>
      </Card>
    </div>
  );
}

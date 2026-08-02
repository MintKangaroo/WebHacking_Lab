import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, CheckCircle2, Network, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";

import {
  checkScope,
  createScope,
  disableWorkspaceExecution,
  enableWorkspaceExecution,
  getProject,
} from "../api/projects";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";

const inputClass = "h-9 rounded-md border border-line bg-black/20 px-3 text-sm text-slate-100 outline-none focus:border-cyan-400/50";

export function ProjectPage() {
  const { projectId = "" } = useParams();
  const queryClient = useQueryClient();
  const [scopeHost, setScopeHost] = useState("");
  const [scopeScheme, setScopeScheme] = useState<"http" | "https">("https");
  const [scopePort, setScopePort] = useState("");
  const [scopePath, setScopePath] = useState("/");
  const [scopeNotes, setScopeNotes] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [checkUrl, setCheckUrl] = useState("http://127.0.0.1:5000/");
  const [executionUse, setExecutionUse] = useState("");
  const [executionConfirmed, setExecutionConfirmed] = useState(false);
  const project = useQuery({ queryKey: ["project", projectId], queryFn: ({ signal }) => getProject(projectId, signal), enabled: Boolean(projectId) });
  const addScope = useMutation({
    mutationFn: () => createScope(projectId, { scheme: scopeScheme, hostname: scopeHost, port: scopePort ? Number(scopePort) : null, path_prefix: scopePath, allow_subdomains: false, authorization_confirmed: confirmed, authorization_notes: scopeNotes }),
    onSuccess: async () => { setScopeHost(""); setScopeNotes(""); setScopePort(""); setScopePath("/"); setConfirmed(false); await queryClient.invalidateQueries({ queryKey: ["project", projectId] }); toast.success("Scope rule registered"); },
    onError: (error: Error) => toast.error(error.message),
  });
  const scopeCheck = useMutation({ mutationFn: () => checkScope(projectId, checkUrl) });
  const enableExecution = useMutation({
    mutationFn: (workspace: { id: string; version: number }) => enableWorkspaceExecution(workspace.id, { authorization_confirmed: true, confirmation_phrase: "ENABLE CONTROLLED REQUESTS", expected_use: executionUse, version: workspace.version }),
    onSuccess: async () => { setExecutionUse(""); setExecutionConfirmed(false); await queryClient.invalidateQueries({ queryKey: ["project", projectId] }); toast.success("Controlled requests enabled for this workspace"); },
    onError: (error: Error) => toast.error(error.message),
  });
  const disableExecution = useMutation({
    mutationFn: (workspace: { id: string; version: number }) => disableWorkspaceExecution(workspace.id, workspace.version),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["project", projectId] }); toast.success("Workspace returned to Analysis Only"); },
    onError: (error: Error) => toast.error(error.message),
  });

  if (project.isLoading) return <div className="p-8 text-sm text-slate-500">Loading project…</div>;
  if (!project.data) return <div className="p-8 text-sm text-red-300">Project could not be loaded.</div>;

  const submit = (event: FormEvent) => { event.preventDefault(); addScope.mutate(); };
  const activeExecution = project.data.workspaces.some((item) => item.network_execution_enabled);
  return (
    <div className="mx-auto max-w-[1500px] space-y-6 p-4 sm:p-6 lg:p-8">
      <header>
        <Link to="/projects" className="inline-flex items-center gap-2 text-xs text-slate-500 hover:text-slate-200"><ArrowLeft className="size-3" /> Projects</Link>
        <div className="mt-4 flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div><div className="flex items-center gap-2"><h1 className="text-2xl font-semibold text-slate-50">{project.data.name}</h1><Badge>{project.data.mode.replaceAll("_", " ")}</Badge></div><p className="mt-2 text-sm text-slate-500">{project.data.description || "No project description"}</p></div>
          <Badge tone={activeExecution ? "warning" : "safe"}><ShieldCheck className="size-3" /> {activeExecution ? "Controlled requests enabled" : "Scope configured · Analysis Only"}</Badge>
        </div>
      </header>

      <section className="grid gap-4 md:grid-cols-3">
        <Card><CardContent className="p-5"><p className="text-xs uppercase tracking-wider text-slate-600">Target hosts</p><p className="mt-2 font-mono text-2xl text-slate-100">{new Set(project.data.scope_rules.map((rule) => rule.hostname)).size}</p></CardContent></Card>
        <Card><CardContent className="p-5"><p className="text-xs uppercase tracking-wider text-slate-600">Request budget</p><p className="mt-2 font-mono text-2xl text-slate-100">{project.data.workspaces.reduce((sum, item) => sum + item.request_budget, 0)}</p></CardContent></Card>
        <Card><CardContent className="p-5"><p className="text-xs uppercase tracking-wider text-slate-600">Network execution</p><p className={`mt-2 flex items-center gap-2 text-sm ${activeExecution ? "text-amber-300" : "text-emerald-300"}`}><CheckCircle2 className="size-4" /> {activeExecution ? "Workspace approved" : "Disabled"}</p></CardContent></Card>
      </section>

      <Card><CardHeader><CardTitle>Controlled request approval</CardTitle></CardHeader><CardContent><div className="grid gap-4 lg:grid-cols-2">{project.data.workspaces.map((workspace) => <div key={workspace.id} className="rounded-lg border border-line bg-black/10 p-4"><div className="flex items-center justify-between gap-3"><div><p className="text-sm font-medium text-slate-200">{workspace.name}</p><p className="mt-1 text-xs text-slate-600">Budget {workspace.requests_used}/{workspace.request_budget} · {workspace.analysis_mode.replaceAll("_", " ")}</p></div><Badge tone={workspace.network_execution_enabled ? "warning" : "safe"}>{workspace.network_execution_enabled ? "Enabled" : "Analysis Only"}</Badge></div>{workspace.network_execution_enabled ? <Button variant="secondary" className="mt-4 w-full" onClick={() => disableExecution.mutate(workspace)} disabled={disableExecution.isPending}>Disable immediately</Button> : <div className="mt-4 space-y-3"><input aria-label={`Execution purpose for ${workspace.name}`} value={executionUse} onChange={(event) => setExecutionUse(event.target.value)} placeholder="Describe the authorized read-only test" className={`${inputClass} w-full`} /><label className="flex gap-2 text-xs leading-5 text-slate-400"><input type="checkbox" checked={executionConfirmed} onChange={(event) => setExecutionConfirmed(event.target.checked)} className="mt-1" />I confirm the target is authorized and every exact request still requires a separate preview.</label><Button className="w-full" onClick={() => enableExecution.mutate(workspace)} disabled={enableExecution.isPending || !executionConfirmed || executionUse.trim().length < 10}>Enable controlled requests</Button></div>}</div>)}</div><p className="mt-4 text-xs leading-5 text-slate-600">The server must also be started with <code className="font-mono text-slate-400">ANALYSIS_ONLY=false</code> and <code className="font-mono text-slate-400">NETWORK_EXECUTION_ENABLED=true</code>. This approval never enables POST bodies, stored credentials, or automatic attack tests.</p></CardContent></Card>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Card><CardHeader><CardTitle className="flex items-center gap-2"><Network className="size-4 text-cyan-400" /> Scope registry</CardTitle></CardHeader><CardContent className="overflow-x-auto"><table className="w-full min-w-[680px] text-left text-sm"><thead className="border-b border-line text-[10px] uppercase tracking-wider text-slate-600"><tr><th className="pb-3">Target</th><th className="pb-3">Path</th><th className="pb-3">Rate</th><th className="pb-3">Concurrency</th><th className="pb-3">Authorization</th></tr></thead><tbody>{project.data.scope_rules.map((rule) => <tr key={rule.id} className="border-b border-line/60"><td className="py-3 font-mono text-xs text-slate-200">{rule.scheme}://{rule.hostname}{rule.port ? `:${rule.port}` : ""}</td><td className="py-3 font-mono text-xs text-slate-400">{rule.path_prefix}</td><td className="py-3 text-slate-400">{rule.max_requests_per_minute}/min</td><td className="py-3 text-slate-400">{rule.max_concurrency}</td><td className="py-3"><Badge tone={rule.authorization_confirmed ? "safe" : "neutral"}>{rule.authorization_confirmed ? "Confirmed" : "Built-in local"}</Badge></td></tr>)}</tbody></table></CardContent></Card>

        <div className="space-y-6">
          <Card><CardHeader><CardTitle>Scope Guard preview</CardTitle></CardHeader><CardContent className="space-y-3"><input aria-label="URL to check" value={checkUrl} onChange={(event) => setCheckUrl(event.target.value)} className={`${inputClass} w-full font-mono text-xs`} /><Button variant="secondary" className="w-full" onClick={() => scopeCheck.mutate()} disabled={scopeCheck.isPending}>Check without sending</Button>{scopeCheck.data && <div className={`rounded-md border p-3 text-xs ${scopeCheck.data.allowed ? "border-emerald-400/20 bg-emerald-400/[0.05] text-emerald-200" : "border-red-400/20 bg-red-400/[0.05] text-red-200"}`}><p className="flex items-center gap-2 font-medium">{scopeCheck.data.allowed ? <ShieldCheck className="size-4" /> : <ShieldAlert className="size-4" />}{scopeCheck.data.code}</p><p className="mt-1 text-current/70">{scopeCheck.data.reason}</p></div>}</CardContent></Card>
          <Card><CardHeader><CardTitle>Register external host</CardTitle></CardHeader><CardContent><form onSubmit={submit} className="space-y-3"><div className="grid grid-cols-[90px_minmax(0,1fr)_90px] gap-2"><select aria-label="Scope scheme" value={scopeScheme} onChange={(event) => setScopeScheme(event.target.value as "http" | "https")} className={inputClass}><option value="https">HTTPS</option><option value="http">HTTP</option></select><input required aria-label="External hostname" value={scopeHost} onChange={(event) => setScopeHost(event.target.value)} placeholder="ctf.example" className={`${inputClass} min-w-0`} /><input aria-label="Scope port" type="number" min="1" max="65535" value={scopePort} onChange={(event) => setScopePort(event.target.value)} placeholder="any" className={`${inputClass} min-w-0`} /></div><input required aria-label="Scope path" value={scopePath} onChange={(event) => setScopePath(event.target.value)} placeholder="/challenge" className={`${inputClass} w-full font-mono text-xs`} /><textarea required minLength={10} aria-label="Authorization notes" value={scopeNotes} onChange={(event) => setScopeNotes(event.target.value)} placeholder="Describe ownership or authorized test scope" className="min-h-20 w-full rounded-md border border-line bg-black/20 p-3 text-sm text-slate-100 outline-none focus:border-cyan-400/50" /><label className="flex gap-2 text-xs leading-5 text-slate-400"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} className="mt-1" />I confirm that I own this system or have explicit permission to test it.</label><Button type="submit" className="w-full" disabled={addScope.isPending || !confirmed}>Register external scope</Button></form></CardContent></Card>
        </div>
      </div>
    </div>
  );
}

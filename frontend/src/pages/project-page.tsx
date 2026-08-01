import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, CheckCircle2, Network, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";

import { checkScope, createScope, getProject } from "../api/projects";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";

const inputClass = "h-9 rounded-md border border-line bg-black/20 px-3 text-sm text-slate-100 outline-none focus:border-cyan-400/50";

export function ProjectPage() {
  const { projectId = "" } = useParams();
  const queryClient = useQueryClient();
  const [scopeHost, setScopeHost] = useState("");
  const [scopeNotes, setScopeNotes] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [checkUrl, setCheckUrl] = useState("http://127.0.0.1:5000/");
  const project = useQuery({ queryKey: ["project", projectId], queryFn: ({ signal }) => getProject(projectId, signal), enabled: Boolean(projectId) });
  const addScope = useMutation({
    mutationFn: () => createScope(projectId, { scheme: "https", hostname: scopeHost, port: null, path_prefix: "/", allow_subdomains: false, authorization_confirmed: confirmed, authorization_notes: scopeNotes }),
    onSuccess: async () => { setScopeHost(""); setScopeNotes(""); setConfirmed(false); await queryClient.invalidateQueries({ queryKey: ["project", projectId] }); toast.success("Scope rule registered"); },
    onError: (error: Error) => toast.error(error.message),
  });
  const scopeCheck = useMutation({ mutationFn: () => checkScope(projectId, checkUrl) });

  if (project.isLoading) return <div className="p-8 text-sm text-slate-500">Loading project…</div>;
  if (!project.data) return <div className="p-8 text-sm text-red-300">Project could not be loaded.</div>;

  const submit = (event: FormEvent) => { event.preventDefault(); addScope.mutate(); };
  return (
    <div className="mx-auto max-w-[1500px] space-y-6 p-4 sm:p-6 lg:p-8">
      <header>
        <Link to="/projects" className="inline-flex items-center gap-2 text-xs text-slate-500 hover:text-slate-200"><ArrowLeft className="size-3" /> Projects</Link>
        <div className="mt-4 flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div><div className="flex items-center gap-2"><h1 className="text-2xl font-semibold text-slate-50">{project.data.name}</h1><Badge>{project.data.mode.replaceAll("_", " ")}</Badge></div><p className="mt-2 text-sm text-slate-500">{project.data.description || "No project description"}</p></div>
          <Badge tone="safe"><ShieldCheck className="size-3" /> Scope configured · Analysis Only</Badge>
        </div>
      </header>

      <section className="grid gap-4 md:grid-cols-3">
        <Card><CardContent className="p-5"><p className="text-xs uppercase tracking-wider text-slate-600">Target hosts</p><p className="mt-2 font-mono text-2xl text-slate-100">{new Set(project.data.scope_rules.map((rule) => rule.hostname)).size}</p></CardContent></Card>
        <Card><CardContent className="p-5"><p className="text-xs uppercase tracking-wider text-slate-600">Request budget</p><p className="mt-2 font-mono text-2xl text-slate-100">{project.data.workspaces.reduce((sum, item) => sum + item.request_budget, 0)}</p></CardContent></Card>
        <Card><CardContent className="p-5"><p className="text-xs uppercase tracking-wider text-slate-600">Network execution</p><p className="mt-2 flex items-center gap-2 text-sm text-emerald-300"><CheckCircle2 className="size-4" /> Disabled</p></CardContent></Card>
      </section>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Card><CardHeader><CardTitle className="flex items-center gap-2"><Network className="size-4 text-cyan-400" /> Scope registry</CardTitle></CardHeader><CardContent className="overflow-x-auto"><table className="w-full min-w-[680px] text-left text-sm"><thead className="border-b border-line text-[10px] uppercase tracking-wider text-slate-600"><tr><th className="pb-3">Target</th><th className="pb-3">Path</th><th className="pb-3">Rate</th><th className="pb-3">Concurrency</th><th className="pb-3">Authorization</th></tr></thead><tbody>{project.data.scope_rules.map((rule) => <tr key={rule.id} className="border-b border-line/60"><td className="py-3 font-mono text-xs text-slate-200">{rule.scheme}://{rule.hostname}{rule.port ? `:${rule.port}` : ""}</td><td className="py-3 font-mono text-xs text-slate-400">{rule.path_prefix}</td><td className="py-3 text-slate-400">{rule.max_requests_per_minute}/min</td><td className="py-3 text-slate-400">{rule.max_concurrency}</td><td className="py-3"><Badge tone={rule.authorization_confirmed ? "safe" : "neutral"}>{rule.authorization_confirmed ? "Confirmed" : "Built-in local"}</Badge></td></tr>)}</tbody></table></CardContent></Card>

        <div className="space-y-6">
          <Card><CardHeader><CardTitle>Scope Guard preview</CardTitle></CardHeader><CardContent className="space-y-3"><input aria-label="URL to check" value={checkUrl} onChange={(event) => setCheckUrl(event.target.value)} className={`${inputClass} w-full font-mono text-xs`} /><Button variant="secondary" className="w-full" onClick={() => scopeCheck.mutate()} disabled={scopeCheck.isPending}>Check without sending</Button>{scopeCheck.data && <div className={`rounded-md border p-3 text-xs ${scopeCheck.data.allowed ? "border-emerald-400/20 bg-emerald-400/[0.05] text-emerald-200" : "border-red-400/20 bg-red-400/[0.05] text-red-200"}`}><p className="flex items-center gap-2 font-medium">{scopeCheck.data.allowed ? <ShieldCheck className="size-4" /> : <ShieldAlert className="size-4" />}{scopeCheck.data.code}</p><p className="mt-1 text-current/70">{scopeCheck.data.reason}</p></div>}</CardContent></Card>
          <Card><CardHeader><CardTitle>Register external host</CardTitle></CardHeader><CardContent><form onSubmit={submit} className="space-y-3"><input required aria-label="External hostname" value={scopeHost} onChange={(event) => setScopeHost(event.target.value)} placeholder="ctf.example" className={`${inputClass} w-full`} /><textarea required minLength={10} aria-label="Authorization notes" value={scopeNotes} onChange={(event) => setScopeNotes(event.target.value)} placeholder="Describe ownership or authorized test scope" className="min-h-20 w-full rounded-md border border-line bg-black/20 p-3 text-sm text-slate-100 outline-none focus:border-cyan-400/50" /><label className="flex gap-2 text-xs leading-5 text-slate-400"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} className="mt-1" />I confirm that I own this system or have explicit permission to test it.</label><Button type="submit" className="w-full" disabled={addScope.isPending || !confirmed}>Register HTTPS scope</Button></form></CardContent></Card>
        </div>
      </div>
    </div>
  );
}

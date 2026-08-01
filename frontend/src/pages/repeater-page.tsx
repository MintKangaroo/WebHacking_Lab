import { useMutation, useQuery } from "@tanstack/react-query";
import { Braces, FileJson, Import, LockKeyhole, Save, TerminalSquare } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { importCurl, importHar, storeRequest } from "../api/http-requests";
import { getProject, getProjects } from "../api/projects";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import type { ImportedExchange } from "../types/resources";

type InputMode = "structured" | "curl" | "har";
const fieldClass = "rounded-md border border-line bg-black/20 px-3 text-sm text-slate-100 outline-none focus:border-cyan-400/50";

export function RepeaterPage() {
  const [mode, setMode] = useState<InputMode>("curl");
  const [projectId, setProjectId] = useState("");
  const [workspaceId, setWorkspaceId] = useState("");
  const [persist, setPersist] = useState(false);
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("http://127.0.0.1:5000/search?q=demo");
  const [headers, setHeaders] = useState("Accept: text/html\nAuthorization: Bearer demo-token");
  const [body, setBody] = useState("");
  const [curl, setCurl] = useState("curl 'http://127.0.0.1:5000/search?q=demo' -H 'Authorization: Bearer demo-token'");
  const [har, setHar] = useState("");
  const [exchange, setExchange] = useState<ImportedExchange | null>(null);
  const projects = useQuery({ queryKey: ["projects"], queryFn: ({ signal }) => getProjects(signal) });
  const project = useQuery({
    queryKey: ["project", projectId],
    queryFn: ({ signal }) => getProject(projectId, signal),
    enabled: Boolean(projectId),
  });

  const processInput = useMutation({
    mutationFn: async () => {
      if (mode === "curl") return importCurl({ command: curl, ...(persist && workspaceId ? { workspace_id: workspaceId } : {}), persist });
      if (mode === "har") return importHar({ content: har, ...(persist && workspaceId ? { workspace_id: workspaceId } : {}), persist });
      if (!workspaceId) throw new Error("Select a workspace before storing a structured request.");
      const parsedHeaders = headers.split("\n").filter(Boolean).map((line) => { const separator = line.indexOf(":"); if (separator < 1) throw new Error("Each header must use Name: Value format."); return { name: line.slice(0, separator).trim(), value: line.slice(separator + 1).trim() }; });
      const stored = await storeRequest({ workspace_id: workspaceId, method, url, headers: parsedHeaders, body });
      return { exchanges: [{ request: stored.normalized, response: null }], request_ids: [], warnings: [] };
    },
    onSuccess: (result) => { setExchange(result.exchanges[0] ?? null); toast.success(persist || mode === "structured" ? "Redacted request stored" : "Import preview generated"); },
    onError: (error: Error) => toast.error(error.message),
  });

  return (
    <div className="flex min-h-[calc(100vh-4rem)] flex-col">
      <header className="sticky top-16 z-10 flex flex-wrap items-center gap-3 border-b border-line bg-canvas/90 px-4 py-3 backdrop-blur sm:px-6">
        <div className="mr-auto"><h1 className="flex items-center gap-2 text-sm font-semibold text-slate-100"><TerminalSquare className="size-4 text-cyan-400" /> HTTP Repeater</h1><p className="mt-1 text-[11px] text-slate-600">Normalize, redact, compare-ready — no network request is sent.</p></div>
        <Badge tone="warning"><LockKeyhole className="size-3" /> Preview only</Badge>
        <Button onClick={() => processInput.mutate()} disabled={processInput.isPending || (persist && !workspaceId)}><Import className="size-3.5" /> {processInput.isPending ? "Processing…" : mode === "structured" ? "Store request" : "Import safely"}</Button>
      </header>

      <div className="grid flex-1 lg:grid-cols-2">
        <section className="border-b border-line p-4 lg:border-b-0 lg:border-r sm:p-6">
          <div className="mb-4 flex flex-wrap items-center gap-2">
            {(["structured", "curl", "har"] as InputMode[]).map((item) => <button key={item} type="button" onClick={() => setMode(item)} className={`rounded-md px-3 py-1.5 text-xs capitalize ${mode === item ? "bg-cyan-400/10 text-cyan-300" : "text-slate-500 hover:bg-white/[0.04]"}`}>{item}</button>)}
            <label className="ml-auto flex items-center gap-2 text-xs text-slate-500"><input type="checkbox" checked={persist} onChange={(event) => setPersist(event.target.checked)} disabled={mode === "structured"} /><Save className="size-3" /> Save revision</label>
          </div>
          {mode === "structured" && <div className="space-y-3"><div className="flex gap-2"><select aria-label="HTTP method" value={method} onChange={(event) => setMethod(event.target.value)} className={`${fieldClass} h-10 w-28`}><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option></select><input aria-label="Request URL" value={url} onChange={(event) => setUrl(event.target.value)} className={`${fieldClass} h-10 min-w-0 flex-1 font-mono text-xs`} /></div><label className="block text-xs text-slate-500">Headers<textarea value={headers} onChange={(event) => setHeaders(event.target.value)} className={`${fieldClass} mt-1.5 min-h-40 w-full p-3 font-mono text-xs leading-6`} /></label><label className="block text-xs text-slate-500">Body<textarea value={body} onChange={(event) => setBody(event.target.value)} className={`${fieldClass} mt-1.5 min-h-48 w-full p-3 font-mono text-xs leading-6`} /></label></div>}
          {mode === "curl" && <label className="block text-xs text-slate-500">cURL text<textarea aria-label="cURL input" value={curl} onChange={(event) => setCurl(event.target.value)} className={`${fieldClass} mt-2 min-h-[430px] w-full resize-y p-4 font-mono text-xs leading-6`} /></label>}
          {mode === "har" && <label className="block text-xs text-slate-500">HAR JSON<textarea aria-label="HAR input" value={har} onChange={(event) => setHar(event.target.value)} placeholder='{"log":{"entries":[]}}' className={`${fieldClass} mt-2 min-h-[430px] w-full resize-y p-4 font-mono text-xs leading-6`} /></label>}
          {(persist || mode === "structured") && <div className="mt-4 grid gap-3 rounded-lg border border-amber-400/15 bg-amber-400/[0.03] p-3 sm:grid-cols-2"><label className="text-xs text-amber-100/70">Project<select aria-label="Project" value={projectId} onChange={(event) => { setProjectId(event.target.value); setWorkspaceId(""); }} className={`${fieldClass} mt-2 h-9 w-full`}><option value="">Select project</option>{projects.data?.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label className="text-xs text-amber-100/70">Workspace<select aria-label="Workspace" value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)} disabled={!project.data} className={`${fieldClass} mt-2 h-9 w-full`}><option value="">Select workspace</option>{project.data?.workspaces.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label></div>}
        </section>

        <section className="min-w-0 bg-black/[0.08] p-4 sm:p-6">
          {!exchange ? <Card className="grid min-h-[460px] place-items-center border-dashed"><div className="max-w-sm text-center"><Braces className="mx-auto size-8 text-slate-700" /><p className="mt-3 text-sm text-slate-400">Normalized preview appears here</p><p className="mt-2 text-xs leading-5 text-slate-600">Sensitive headers, cookies, query values, and structured body fields are masked before returning from the API.</p></div></Card> : <div className="space-y-4"><div className="flex flex-wrap items-center gap-2"><Badge tone="safe">{exchange.request.method}</Badge><span className="break-all font-mono text-xs text-slate-300">{exchange.request.scheme}://{exchange.request.host}:{exchange.request.port}{exchange.request.path}</span></div><Card className="overflow-hidden"><div className="flex items-center gap-2 border-b border-line px-4 py-3 text-xs font-medium text-slate-300"><Braces className="size-3.5 text-violet-300" /> Normalized request</div><pre className="max-h-[420px] overflow-auto p-4 font-mono text-[11px] leading-5 text-slate-400">{JSON.stringify(exchange.request, null, 2)}</pre></Card>{exchange.response && <Card className="overflow-hidden"><div className="flex items-center gap-2 border-b border-line px-4 py-3 text-xs font-medium text-slate-300"><FileJson className="size-3.5 text-emerald-300" /> Imported response · {exchange.response.status_code}</div><pre className="max-h-72 overflow-auto p-4 font-mono text-[11px] leading-5 text-slate-400">{JSON.stringify(exchange.response, null, 2)}</pre></Card>}</div>}
        </section>
      </div>
    </div>
  );
}

import { Background, Controls, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Activity,
  Braces,
  FileJson,
  GitCompareArrows,
  Import,
  LockKeyhole,
  Play,
  Save,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { compareResponses, runAnalysis } from "../api/analysis";
import {
  executeRequest,
  getRequest,
  importCurl,
  importHar,
  previewRequestExecution,
  storeRequest,
} from "../api/http-requests";
import { getProject, getProjects } from "../api/projects";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card } from "../components/ui/card";
import type {
  AnalysisRun,
  HttpRequestRecord,
  ImportedExchange,
  RequestExecutionPreview,
  ResponseDiff,
} from "../types/resources";

type InputMode = "structured" | "curl" | "har";
type ProcessedInput = {
  exchange: ImportedExchange;
  request: HttpRequestRecord | null;
};

const fieldClass =
  "rounded-md border border-line bg-black/20 px-3 text-sm text-slate-100 outline-none focus:border-cyan-400/50";

function parseHeaders(value: string) {
  return value
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const separator = line.indexOf(":");
      if (separator < 1) throw new Error("Each header must use Name: Value format.");
      return {
        name: line.slice(0, separator).trim(),
        value: line.slice(separator + 1).trim(),
      };
    });
}

function statusTone(status: string): "safe" | "warning" | "critical" | "neutral" {
  if (status === "likely" || status === "confirmed") return "critical";
  if (status === "suspicious") return "warning";
  if (status === "observation") return "safe";
  return "neutral";
}

export function RepeaterPage() {
  const [mode, setMode] = useState<InputMode>("curl");
  const [projectId, setProjectId] = useState("");
  const [workspaceId, setWorkspaceId] = useState("");
  const [persist, setPersist] = useState(false);
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("http://127.0.0.1:5000/search?q=demo");
  const [headers, setHeaders] = useState(
    "Accept: text/html\nAuthorization: Bearer demo-token",
  );
  const [body, setBody] = useState("");
  const [curl, setCurl] = useState(
    "curl 'http://127.0.0.1:5000/search?q=demo' -H 'Authorization: Bearer demo-token'",
  );
  const [har, setHar] = useState("");
  const [exchange, setExchange] = useState<ImportedExchange | null>(null);
  const [storedRequest, setStoredRequest] = useState<HttpRequestRecord | null>(null);
  const [executionPreview, setExecutionPreview] =
    useState<RequestExecutionPreview | null>(null);
  const [approvalChecked, setApprovalChecked] = useState(false);
  const [analysis, setAnalysis] = useState<AnalysisRun | null>(null);
  const [diff, setDiff] = useState<ResponseDiff | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: ({ signal }) => getProjects(signal),
  });
  const project = useQuery({
    queryKey: ["project", projectId],
    queryFn: ({ signal }) => getProject(projectId, signal),
    enabled: Boolean(projectId),
  });
  const selectedWorkspace = project.data?.workspaces.find(
    (item) => item.id === workspaceId,
  );

  const processInput = useMutation({
    mutationFn: async (): Promise<ProcessedInput> => {
      if (mode === "structured") {
        if (!workspaceId) throw new Error("Select a workspace before storing a request.");
        const stored = await storeRequest({
          workspace_id: workspaceId,
          method,
          url,
          headers: parseHeaders(headers),
          body,
        });
        return { exchange: { request: stored.normalized, response: null }, request: stored };
      }
      const result =
        mode === "curl"
          ? await importCurl({
              command: curl,
              ...(persist && workspaceId ? { workspace_id: workspaceId } : {}),
              persist,
            })
          : await importHar({
              content: har,
              ...(persist && workspaceId ? { workspace_id: workspaceId } : {}),
              persist,
            });
      const importedExchange = result.exchanges[0];
      if (!importedExchange) throw new Error("The import did not contain an HTTP exchange.");
      const requestId = result.request_ids[0];
      if (!requestId) return { exchange: importedExchange, request: null };
      const stored = await getRequest(requestId);
      return {
        exchange: {
          request: stored.normalized,
          response: stored.responses.at(-1)?.normalized ?? importedExchange.response,
        },
        request: stored,
      };
    },
    onSuccess: (result) => {
      setExchange(result.exchange);
      setStoredRequest(result.request);
      setExecutionPreview(null);
      setAnalysis(null);
      setDiff(null);
      toast.success(result.request ? "Redacted request stored" : "Import preview generated");
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const previewExecution = useMutation({
    mutationFn: async () => {
      if (!storedRequest) throw new Error("Store the request before reviewing execution.");
      return previewRequestExecution(storedRequest.id);
    },
    onSuccess: (result) => {
      setExecutionPreview(result);
      setApprovalChecked(false);
      toast.success("Exact request preview generated without sending");
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const execute = useMutation({
    mutationFn: async () => {
      if (!storedRequest || !executionPreview) throw new Error("Review the request first.");
      return executeRequest(storedRequest.id, {
        confirmation_phrase: "SEND UP TO 5 SAFE REQUESTS",
        approval_token: executionPreview.approval_token,
        request_version: storedRequest.version,
      });
    },
    onSuccess: (result) => {
      setExchange((current) =>
        current ? { ...current, response: result.response.normalized } : current,
      );
      setStoredRequest((current) =>
        current
          ? { ...current, responses: [...current.responses, result.response] }
          : current,
      );
      setExecutionPreview(null);
      setApprovalChecked(false);
      toast.success(
        `Controlled request completed · budget ${result.requests_used}/${result.request_budget}`,
      );
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const analyze = useMutation({
    mutationFn: async () => {
      if (!storedRequest) throw new Error("Store the request before analysis.");
      return runAnalysis(storedRequest.id, storedRequest.responses.at(-1)?.id);
    },
    onSuccess: (result) => {
      setAnalysis(result);
      setSelectedNodeId(result.flow.nodes[0]?.id ?? null);
      toast.success("Six passive analyzers completed");
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const compare = useMutation({
    mutationFn: async () => {
      if (!storedRequest || storedRequest.responses.length < 2) {
        throw new Error("At least two persisted responses are required.");
      }
      const baseline = storedRequest.responses.at(-2);
      const test = storedRequest.responses.at(-1);
      if (!baseline || !test) throw new Error("Two responses could not be selected.");
      return compareResponses(baseline.id, test.id);
    },
    onSuccess: (result) => {
      setDiff(result.result);
      toast.success("Structured response diff completed");
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const flowNodes = useMemo<Node[]>(
    () =>
      (analysis?.flow.nodes ?? []).map((node, index) => ({
        id: node.id,
        position: {
          x: index < 2 ? index * 240 : ((index - 2) % 2) * 280,
          y: index < 2 ? 20 : 130 + Math.floor((index - 2) / 2) * 115,
        },
        data: { label: node.label },
        style: {
          width: 220,
          border: "1px solid rgba(34,211,238,.2)",
          borderRadius: 8,
          background: "#101720",
          color: "#cbd5e1",
          fontSize: 11,
        },
      })),
    [analysis],
  );
  const flowEdges = useMemo<Edge[]>(
    () =>
      (analysis?.flow.edges ?? []).map((edge) => ({
        ...edge,
        animated: edge.source === "normalize",
        style: { stroke: "#334155" },
      })),
    [analysis],
  );
  const selectedFlowNode = analysis?.flow.nodes.find((node) => node.id === selectedNodeId);

  return (
    <div className="flex min-h-[calc(100vh-4rem)] flex-col">
      <header className="sticky top-16 z-10 flex flex-wrap items-center gap-3 border-b border-line bg-canvas/90 px-4 py-3 backdrop-blur sm:px-6">
        <div className="mr-auto">
          <h1 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <TerminalSquare className="size-4 text-cyan-400" /> HTTP Repeater
          </h1>
          <p className="mt-1 text-[11px] text-slate-600">
            Import → redact → review → controlled request → passive analysis
          </p>
        </div>
        <Badge tone={selectedWorkspace?.network_execution_enabled ? "warning" : "safe"}>
          <LockKeyhole className="size-3" />
          {selectedWorkspace?.network_execution_enabled ? "Approval required" : "Analysis Only"}
        </Badge>
        <Button
          onClick={() => processInput.mutate()}
          disabled={processInput.isPending || ((persist || mode === "structured") && !workspaceId)}
        >
          <Import className="size-3.5" />
          {processInput.isPending
            ? "Processing…"
            : mode === "structured"
              ? "Store request"
              : persist
                ? "Import & save"
                : "Import safely"}
        </Button>
      </header>

      <div className="grid flex-1 lg:grid-cols-2">
        <section className="border-b border-line p-4 lg:border-b-0 lg:border-r sm:p-6">
          <div className="mb-4 flex flex-wrap items-center gap-2">
            {(["structured", "curl", "har"] as InputMode[]).map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => setMode(item)}
                className={`rounded-md px-3 py-1.5 text-xs capitalize ${mode === item ? "bg-cyan-400/10 text-cyan-300" : "text-slate-500 hover:bg-white/[0.04]"}`}
              >
                {item}
              </button>
            ))}
            <label className="ml-auto flex items-center gap-2 text-xs text-slate-500">
              <input
                type="checkbox"
                checked={persist || mode === "structured"}
                onChange={(event) => setPersist(event.target.checked)}
                disabled={mode === "structured"}
              />
              <Save className="size-3" /> Save for analysis
            </label>
          </div>

          {mode === "structured" && (
            <div className="space-y-3">
              <div className="flex gap-2">
                <select
                  aria-label="HTTP method"
                  value={method}
                  onChange={(event) => setMethod(event.target.value)}
                  className={`${fieldClass} h-10 w-28`}
                >
                  <option>GET</option><option>HEAD</option><option>OPTIONS</option>
                  <option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option>
                </select>
                <input
                  aria-label="Request URL"
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  className={`${fieldClass} h-10 min-w-0 flex-1 font-mono text-xs`}
                />
              </div>
              <label className="block text-xs text-slate-500">
                Headers
                <textarea
                  value={headers}
                  onChange={(event) => setHeaders(event.target.value)}
                  className={`${fieldClass} mt-1.5 min-h-40 w-full p-3 font-mono text-xs leading-6`}
                />
              </label>
              <label className="block text-xs text-slate-500">
                Body
                <textarea
                  value={body}
                  onChange={(event) => setBody(event.target.value)}
                  className={`${fieldClass} mt-1.5 min-h-48 w-full p-3 font-mono text-xs leading-6`}
                />
              </label>
            </div>
          )}
          {mode === "curl" && (
            <label className="block text-xs text-slate-500">
              cURL text
              <textarea
                aria-label="cURL input"
                value={curl}
                onChange={(event) => setCurl(event.target.value)}
                className={`${fieldClass} mt-2 min-h-[360px] w-full resize-y p-4 font-mono text-xs leading-6`}
              />
            </label>
          )}
          {mode === "har" && (
            <label className="block text-xs text-slate-500">
              HAR JSON
              <textarea
                aria-label="HAR input"
                value={har}
                onChange={(event) => setHar(event.target.value)}
                placeholder='{"log":{"entries":[]}}'
                className={`${fieldClass} mt-2 min-h-[360px] w-full resize-y p-4 font-mono text-xs leading-6`}
              />
            </label>
          )}

          <div className="mt-4 grid gap-3 rounded-lg border border-amber-400/15 bg-amber-400/[0.03] p-3 sm:grid-cols-2">
            <label className="text-xs text-amber-100/70">
              Project
              <select
                aria-label="Project"
                value={projectId}
                onChange={(event) => {
                  setProjectId(event.target.value);
                  setWorkspaceId("");
                }}
                className={`${fieldClass} mt-2 h-9 w-full`}
              >
                <option value="">Preview only</option>
                {projects.data?.map((item) => (
                  <option key={item.id} value={item.id}>{item.name}</option>
                ))}
              </select>
            </label>
            <label className="text-xs text-amber-100/70">
              Workspace
              <select
                aria-label="Workspace"
                value={workspaceId}
                onChange={(event) => setWorkspaceId(event.target.value)}
                disabled={!project.data}
                className={`${fieldClass} mt-2 h-9 w-full`}
              >
                <option value="">Select workspace</option>
                {project.data?.workspaces.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name} · {item.network_execution_enabled ? "controlled" : "analysis only"}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </section>

        <section className="min-w-0 space-y-4 bg-black/[0.08] p-4 sm:p-6">
          {!exchange ? (
            <Card className="grid min-h-[460px] place-items-center border-dashed">
              <div className="max-w-sm text-center">
                <Braces className="mx-auto size-8 text-slate-700" />
                <p className="mt-3 text-sm text-slate-400">Normalized preview appears here</p>
                <p className="mt-2 text-xs leading-5 text-slate-600">
                  Sensitive headers, cookies, query values, and body fields are masked by the API.
                </p>
              </div>
            </Card>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone="safe">{exchange.request.method}</Badge>
                <span className="break-all font-mono text-xs text-slate-300">
                  {exchange.request.scheme}://{exchange.request.host}:{exchange.request.port}
                  {exchange.request.path}
                </span>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="secondary"
                  onClick={() => previewExecution.mutate()}
                  disabled={!storedRequest || previewExecution.isPending}
                >
                  <ShieldCheck className="size-3.5" /> Review exact request
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => analyze.mutate()}
                  disabled={!storedRequest || analyze.isPending}
                >
                  <Activity className="size-3.5" /> Run 6 analyzers
                </Button>
                <Button
                  variant="secondary"
                  onClick={() => compare.mutate()}
                  disabled={(storedRequest?.responses.length ?? 0) < 2 || compare.isPending}
                >
                  <GitCompareArrows className="size-3.5" /> Compare last 2
                </Button>
              </div>
              <Card className="overflow-hidden">
                <div className="flex items-center gap-2 border-b border-line px-4 py-3 text-xs font-medium text-slate-300">
                  <Braces className="size-3.5 text-violet-300" /> Normalized request
                </div>
                <pre className="max-h-80 overflow-auto p-4 font-mono text-[11px] leading-5 text-slate-400">
                  {JSON.stringify(exchange.request, null, 2)}
                </pre>
              </Card>
              {exchange.response && (
                <Card className="overflow-hidden">
                  <div className="flex items-center gap-2 border-b border-line px-4 py-3 text-xs font-medium text-slate-300">
                    <FileJson className="size-3.5 text-emerald-300" /> Imported response · {exchange.response.status_code}
                  </div>
                  <pre className="max-h-72 overflow-auto p-4 font-mono text-[11px] leading-5 text-slate-400">
                    {JSON.stringify(exchange.response, null, 2)}
                  </pre>
                </Card>
              )}
            </>
          )}

          {executionPreview && (
            <Card className="overflow-hidden border-amber-400/20">
              <div className="border-b border-amber-400/15 bg-amber-400/[0.04] px-4 py-3">
                <p className="text-xs font-semibold text-amber-200">Final approval · no automatic tests</p>
                <p className="mt-1 text-[11px] text-amber-100/50">
                  Max {executionPreview.maximum_request_count} requests · TLS verified · no data change
                </p>
              </div>
              <pre className="max-h-64 overflow-auto p-4 font-mono text-[11px] leading-5 text-slate-300">
                {executionPreview.exact_request}
              </pre>
              <div className="space-y-3 border-t border-line p-4">
                <p className="text-xs leading-5 text-slate-500">{executionPreview.expected_impact}</p>
                {executionPreview.warnings.map((warning) => (
                  <p key={warning} className="text-xs text-amber-300/70">• {warning}</p>
                ))}
                <label className="flex gap-2 text-xs leading-5 text-slate-300">
                  <input
                    type="checkbox"
                    checked={approvalChecked}
                    onChange={(event) => setApprovalChecked(event.target.checked)}
                    className="mt-1"
                  />
                  I reviewed the exact request, target, impact, redirect limit, and Scope Guard result.
                </label>
                <Button
                  onClick={() => execute.mutate()}
                  disabled={!approvalChecked || execute.isPending}
                  className="w-full"
                >
                  <Play className="size-3.5" /> Send controlled request
                </Button>
              </div>
            </Card>
          )}

          {diff && (
            <Card className="p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm font-medium text-slate-200">Response diff</p>
                <Badge tone={diff.status_changed ? "warning" : "safe"}>
                  Similarity {(diff.body_similarity * 100).toFixed(1)}%
                </Badge>
              </div>
              <div className="mt-3 grid grid-cols-3 gap-2 text-center text-xs">
                <div className="rounded bg-white/[0.03] p-2 text-slate-400">{diff.baseline_status} → {diff.test_status}</div>
                <div className="rounded bg-white/[0.03] p-2 text-slate-400">{diff.body_size_delta >= 0 ? "+" : ""}{diff.body_size_delta} B</div>
                <div className="rounded bg-white/[0.03] p-2 text-slate-400">{diff.header_differences.length} headers</div>
              </div>
              {diff.unified_body_diff && <pre className="mt-3 max-h-52 overflow-auto rounded bg-black/20 p-3 font-mono text-[10px] leading-5 text-slate-500">{diff.unified_body_diff}</pre>}
            </Card>
          )}

          {analysis && (
            <Card className="overflow-hidden">
              <div className="border-b border-line px-4 py-3">
                <p className="text-sm font-medium text-slate-200">Passive analysis workflow</p>
                <p className="mt-1 text-[11px] text-slate-600">Candidates are observations, not automatic confirmation.</p>
              </div>
              <div className="h-[430px] bg-[#090e14]">
                <ReactFlow
                  nodes={flowNodes}
                  edges={flowEdges}
                  fitView
                  minZoom={0.4}
                  onNodeClick={(_event, node) => setSelectedNodeId(node.id)}
                >
                  <Background color="#1e293b" gap={20} />
                  <Controls showInteractive={false} />
                </ReactFlow>
              </div>
              {selectedFlowNode && (
                <div className="border-t border-line p-4">
                  <div className="flex items-center gap-2">
                    <Badge tone={statusTone(selectedFlowNode.status)}>{selectedFlowNode.status}</Badge>
                    <p className="text-sm font-medium text-slate-200">{selectedFlowNode.label}</p>
                  </div>
                  <p className="mt-2 text-xs leading-5 text-slate-500">{selectedFlowNode.detail}</p>
                  {selectedFlowNode.confidence !== null && (
                    <p className="mt-2 font-mono text-[11px] text-cyan-300">
                      Confidence {(selectedFlowNode.confidence * 100).toFixed(0)}%
                    </p>
                  )}
                </div>
              )}
              <div className="grid gap-2 border-t border-line p-4 sm:grid-cols-2">
                {analysis.results.map((result) => (
                  <div key={result.analyzer} className="rounded-md border border-line bg-black/10 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-xs font-medium text-slate-300">{result.title}</p>
                      <Badge tone={statusTone(result.status)}>{result.status}</Badge>
                    </div>
                    <p className="mt-2 text-[11px] leading-5 text-slate-600">{result.summary}</p>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </section>
      </div>
    </div>
  );
}

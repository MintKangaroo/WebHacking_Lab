import Editor, { type OnMount } from "@monaco-editor/react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Braces,
  CheckCircle2,
  ChevronRight,
  FileArchive,
  FileCode2,
  FolderTree,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Play,
  Route,
  Search,
  ShieldCheck,
  Upload,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { toast } from "sonner";

import {
  analyzeCodeProject,
  createCodeProject,
  getCodeAnalysis,
  getCodeFile,
  getCodeFiles,
  getCodeProjects,
  getCodeRoutes,
  uploadCodeProject,
} from "../api/code-projects";
import { getProjects } from "../api/projects";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import type { CodeProject, StaticRoute } from "../types/resources";
import { cn } from "../utils/cn";

const fieldClass =
  "h-10 w-full rounded-md border border-line bg-black/20 px-3 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-400/50";

function formatBytes(value: number) {
  if (value < 1_000) return `${value} B`;
  if (value < 1_000_000) return `${(value / 1_000).toFixed(1)} KB`;
  return `${(value / 1_000_000).toFixed(1)} MB`;
}

function statusTone(status: CodeProject["status"]) {
  if (status === "completed") return "safe" as const;
  if (status === "failed") return "critical" as const;
  if (status === "analyzing") return "accent" as const;
  return "warning" as const;
}

function UploadPanel({
  selectedParentId,
}: {
  selectedParentId: string;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("Uploaded Web Challenge");
  const [description, setDescription] = useState("Authorized source review without execution");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [confirmed, setConfirmed] = useState(false);

  const createAndUpload = useMutation({
    mutationFn: async () => {
      const project = await createCodeProject({
        project_id: selectedParentId,
        name: name.trim(),
        description: description.trim(),
        authorization_confirmed: true,
        authorization_notes: description.trim(),
        confirmation_phrase: "UPLOAD INERT SOURCE",
      });
      return uploadCodeProject(project.id, selectedFiles);
    },
    onSuccess: async (result) => {
      setSelectedFiles([]);
      setConfirmed(false);
      await queryClient.invalidateQueries({ queryKey: ["code-projects"] });
      toast.success(`${result.files.length} inert source files indexed`);
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (
      !selectedParentId ||
      !name.trim() ||
      description.trim().length < 10 ||
      !selectedFiles.length ||
      !confirmed
    )
      return;
    createAndUpload.mutate();
  };

  return (
    <Card className="border-cyan-400/15 bg-cyan-400/[0.025]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">
          <Upload className="size-4 text-cyan-300" /> New source upload
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="grid gap-3 xl:grid-cols-[1fr_1fr_1.3fr_auto]">
          <label className="space-y-1.5 text-xs text-slate-500">
            Analysis name
            <input
              aria-label="Analysis name"
              className={fieldClass}
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label className="space-y-1.5 text-xs text-slate-500">
            Purpose
            <input
              aria-label="Source review purpose"
              className={fieldClass}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              minLength={10}
              required
            />
          </label>
          <label className="space-y-1.5 text-xs text-slate-500">
            Source files or one ZIP
            <input
              aria-label="Source files"
              className="block h-10 w-full rounded-md border border-dashed border-slate-700 bg-black/20 px-3 py-2 text-xs text-slate-400 file:mr-3 file:border-0 file:bg-transparent file:text-cyan-300"
              type="file"
              multiple
              accept=".zip,.py,.php,.js,.jsx,.mjs,.ts,.tsx,.java,.json,.toml,.xml,.yml,.yaml,.txt,.md,.html,.css,.sql,.gradle"
              onChange={(event) => setSelectedFiles(Array.from(event.target.files ?? []))}
            />
          </label>
          <Button
            type="submit"
            className="self-end"
            disabled={
              !selectedParentId ||
              !name.trim() ||
              description.trim().length < 10 ||
              !selectedFiles.length ||
              !confirmed ||
              createAndUpload.isPending
            }
          >
            {createAndUpload.isPending ? (
              <LoaderCircle className="size-4 animate-spin" />
            ) : (
              <FileArchive className="size-4" />
            )}
            Validate & index
          </Button>
          <label className="flex items-start gap-2 text-xs text-slate-500 xl:col-span-4">
            <input
              aria-label="Confirm source authorization"
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
              className="mt-0.5 accent-cyan-400"
            />
            I own this source or have explicit review permission. Files remain inert; dependencies
            are not installed and uploaded code is never executed.
          </label>
        </form>
      </CardContent>
    </Card>
  );
}

export function CodeAnalysisPage() {
  const queryClient = useQueryClient();
  const editorRef = useRef<Parameters<OnMount>[0] | null>(null);
  const [parentId, setParentId] = useState("");
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [selectedFileId, setSelectedFileId] = useState("");
  const [selectedRouteId, setSelectedRouteId] = useState("");
  const [filter, setFilter] = useState("");

  const parents = useQuery({ queryKey: ["projects"], queryFn: ({ signal }) => getProjects(signal) });
  const effectiveParentId = parentId || parents.data?.[0]?.id || "";
  const projects = useQuery({
    queryKey: ["code-projects", effectiveParentId],
    queryFn: ({ signal }) => getCodeProjects(effectiveParentId, signal),
    enabled: Boolean(effectiveParentId),
  });
  const effectiveProjectId =
    projects.data?.find((value) => value.id === selectedProjectId)?.id ??
    projects.data?.[0]?.id ??
    "";
  const selectedProject = projects.data?.find((value) => value.id === effectiveProjectId);
  const files = useQuery({
    queryKey: ["code-files", effectiveProjectId],
    queryFn: ({ signal }) => getCodeFiles(effectiveProjectId, signal),
    enabled: Boolean(effectiveProjectId),
  });
  const routes = useQuery({
    queryKey: ["code-routes", effectiveProjectId],
    queryFn: ({ signal }) => getCodeRoutes(effectiveProjectId, signal),
    enabled: Boolean(effectiveProjectId),
  });
  const effectiveFileId =
    files.data?.find((value) => value.id === selectedFileId)?.id ?? files.data?.[0]?.id ?? "";
  const file = useQuery({
    queryKey: ["code-file", effectiveProjectId, effectiveFileId],
    queryFn: ({ signal }) => getCodeFile(effectiveProjectId, effectiveFileId, signal),
    enabled: Boolean(effectiveProjectId && effectiveFileId),
  });
  const analysis = useQuery({
    queryKey: ["code-analysis", effectiveProjectId],
    queryFn: ({ signal }) => getCodeAnalysis(effectiveProjectId, signal),
    enabled: Boolean(effectiveProjectId && selectedProject?.status === "completed"),
  });
  const selectedRoute = routes.data?.find((value) => value.id === selectedRouteId);

  const analyze = useMutation({
    mutationFn: () => analyzeCodeProject(effectiveProjectId),
    onSuccess: async (result) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["code-projects"] }),
        queryClient.invalidateQueries({ queryKey: ["code-routes", effectiveProjectId] }),
        queryClient.invalidateQueries({ queryKey: ["code-files", effectiveProjectId] }),
        queryClient.invalidateQueries({ queryKey: ["code-analysis", effectiveProjectId] }),
      ]);
      toast.success(`${result.routes.length} static routes extracted`);
    },
    onError: (error: Error) => toast.error(error.message),
  });

  useEffect(() => {
    if (selectedRoute) editorRef.current?.revealLineInCenter(selectedRoute.line_start);
  }, [selectedRoute, file.data]);

  const filteredFiles = useMemo(
    () =>
      files.data?.filter((value) =>
        value.relative_path.toLowerCase().includes(filter.toLowerCase()),
      ) ?? [],
    [files.data, filter],
  );

  const selectRoute = (route: StaticRoute) => {
    setSelectedRouteId(route.id);
    setSelectedFileId(route.code_file_id);
  };

  return (
    <div className="mx-auto max-w-[1800px] space-y-5 p-4 sm:p-6 lg:p-8">
      <header className="flex flex-col justify-between gap-4 xl:flex-row xl:items-end">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-400/70">
            Phase 10 · inert static inventory
          </p>
          <h1 className="mt-2 text-2xl font-semibold text-slate-50">Code Analysis</h1>
          <p className="mt-1 max-w-3xl text-sm text-slate-500">
            Upload untrusted source, identify frameworks, and map routes to code without running
            the project or installing dependencies.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="safe"><LockKeyhole className="size-3" /> No execution</Badge>
          <Badge tone="accent"><ShieldCheck className="size-3" /> ZIP guarded</Badge>
          <select
            aria-label="Parent project"
            className={cn(fieldClass, "min-w-52")}
            value={effectiveParentId}
            onChange={(event) => {
              setParentId(event.target.value);
              setSelectedProjectId("");
            }}
          >
            {parents.data?.map((value) => (
              <option key={value.id} value={value.id}>{value.name}</option>
            ))}
          </select>
        </div>
      </header>

      <UploadPanel selectedParentId={effectiveParentId} />

      <section className="grid min-h-[720px] gap-4 xl:grid-cols-[280px_minmax(0,1fr)_330px]">
        <Card className="overflow-hidden">
          <CardHeader className="space-y-3">
            <CardTitle className="flex items-center gap-2 text-sm">
              <FolderTree className="size-4 text-violet-300" /> Project files
            </CardTitle>
            <select
              aria-label="Code project"
              className={fieldClass}
              value={effectiveProjectId}
              onChange={(event) => {
                setSelectedProjectId(event.target.value);
                setSelectedFileId("");
                setSelectedRouteId("");
              }}
            >
              {!projects.data?.length && <option value="">No source projects</option>}
              {projects.data?.map((value) => (
                <option key={value.id} value={value.id}>{value.name}</option>
              ))}
            </select>
            <label className="relative block">
              <Search className="absolute left-3 top-2.5 size-3.5 text-slate-600" />
              <input
                aria-label="Filter files"
                className={cn(fieldClass, "pl-9")}
                placeholder="Filter files"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
              />
            </label>
          </CardHeader>
          <CardContent className="max-h-[580px] space-y-1 overflow-y-auto p-2">
            {filteredFiles.map((value) => (
              <button
                key={value.id}
                type="button"
                onClick={() => {
                  setSelectedFileId(value.id);
                  setSelectedRouteId("");
                }}
                className={cn(
                  "flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-xs",
                  effectiveFileId === value.id
                    ? "bg-cyan-400/[0.08] text-cyan-200"
                    : "text-slate-400 hover:bg-white/[0.03]",
                )}
              >
                <FileCode2 className="size-3.5 shrink-0" />
                <span className="min-w-0 flex-1 truncate font-mono">{value.relative_path}</span>
                {value.secret_findings_count > 0 && (
                  <KeyRound className="size-3 text-amber-300" aria-label="Secret warning" />
                )}
                {value.route_count > 0 && <span className="text-[10px]">{value.route_count}</span>}
              </button>
            ))}
            {!filteredFiles.length && (
              <div className="py-12 text-center text-xs text-slate-600">Upload source to begin</div>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4 overflow-hidden">
          <Card className="overflow-hidden">
            <div className="flex h-11 items-center gap-2 border-b border-line px-4">
              <Braces className="size-4 text-cyan-300" />
              <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-300">
                {file.data?.relative_path ?? "Select a source file"}
              </span>
              {file.data?.redacted && <Badge tone="warning">Secrets masked</Badge>}
              {file.data?.truncated && <Badge tone="warning">Preview truncated</Badge>}
            </div>
            <Editor
              height="470px"
              theme="vs-dark"
              language={file.data?.language === "python" ? "python" : file.data?.language}
              value={file.data?.content ?? "// Source preview appears here after upload."}
              onMount={(editor) => { editorRef.current = editor; }}
              options={{
                readOnly: true,
                minimap: { enabled: false },
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 12,
                lineNumbersMinChars: 3,
                scrollBeyondLastLine: false,
                renderLineHighlight: "all",
                wordWrap: "on",
              }}
            />
          </Card>
          <Card>
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <CardTitle className="flex items-center gap-2 text-sm">
                <Route className="size-4 text-violet-300" /> Route inventory
              </CardTitle>
              <Button
                size="sm"
                onClick={() => analyze.mutate()}
                disabled={!effectiveProjectId || selectedProject?.status === "empty" || analyze.isPending}
              >
                {analyze.isPending ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-4" />}
                Analyze routes
              </Button>
            </CardHeader>
            <CardContent className="grid max-h-52 gap-2 overflow-y-auto sm:grid-cols-2">
              {routes.data?.map((route) => (
                <button
                  key={route.id}
                  type="button"
                  onClick={() => selectRoute(route)}
                  className={cn(
                    "flex items-center gap-2 rounded-lg border p-2.5 text-left",
                    selectedRouteId === route.id
                      ? "border-violet-400/30 bg-violet-400/[0.06]"
                      : "border-line bg-black/10 hover:bg-white/[0.025]",
                  )}
                >
                  <Badge tone="accent">{route.methods.join("/")}</Badge>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-300">{route.path}</span>
                  <ChevronRight className="size-3 text-slate-700" />
                </button>
              ))}
              {!routes.data?.length && (
                <p className="col-span-full py-5 text-center text-xs text-slate-600">
                  Run route analysis after a guarded upload.
                </p>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between text-sm">
                Project inspector
                {selectedProject && <Badge tone={statusTone(selectedProject.status)}>{selectedProject.status}</Badge>}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-2">
                <div className="rounded-md border border-line bg-black/15 p-2.5">
                  <p className="font-mono text-base text-slate-100">{selectedProject?.total_files ?? 0}</p>
                  <p className="text-slate-600">Files</p>
                </div>
                <div className="rounded-md border border-line bg-black/15 p-2.5">
                  <p className="font-mono text-base text-slate-100">{formatBytes(selectedProject?.total_bytes ?? 0)}</p>
                  <p className="text-slate-600">Indexed text</p>
                </div>
              </div>
              <div>
                <p className="mb-2 text-slate-600">Framework signals</p>
                <div className="flex flex-wrap gap-1.5">
                  {selectedProject?.frameworks.map((value) => <Badge key={value} tone="accent">{value}</Badge>)}
                  {!selectedProject?.frameworks.length && <span className="text-slate-700">Not detected</span>}
                </div>
              </div>
              {(selectedProject?.secret_findings_count ?? 0) > 0 && (
                <div className="rounded-lg border border-amber-400/20 bg-amber-400/[0.05] p-3 text-amber-200">
                  <p className="flex items-center gap-2 font-medium"><AlertTriangle className="size-4" /> Secret-shaped values masked</p>
                  <p className="mt-1 text-amber-200/60">{selectedProject?.secret_findings_count} location(s); values are not returned to the editor.</p>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">Route details</CardTitle></CardHeader>
            <CardContent className="space-y-3 text-xs">
              {selectedRoute ? (
                <>
                  <div><p className="text-slate-600">Endpoint</p><p className="mt-1 font-mono text-cyan-200">{selectedRoute.methods.join(", ")} {selectedRoute.path}</p></div>
                  <div><p className="text-slate-600">Handler</p><p className="mt-1 font-mono text-slate-300">{selectedRoute.handler_name} · {selectedRoute.file_path}:{selectedRoute.line_start}</p></div>
                  <div><p className="text-slate-600">Parameters</p><div className="mt-1 flex flex-wrap gap-1">{selectedRoute.parameters.map((value) => <Badge key={`${value.location}:${value.name}`}>{value.location}:{value.name}</Badge>)}</div></div>
                  <div className="flex items-center gap-2 text-slate-400">
                    {selectedRoute.authentication.required ? <ShieldCheck className="size-4 text-emerald-300" /> : <AlertTriangle className="size-4 text-amber-300" />}
                    Auth {selectedRoute.authentication.required ? "signal observed" : "not proven"}
                  </div>
                </>
              ) : (
                <p className="py-6 text-center text-slate-600">Select a route to inspect its code mapping.</p>
              )}
            </CardContent>
          </Card>

          <Card className="border-emerald-400/15 bg-emerald-400/[0.025]">
            <CardContent className="space-y-2 p-4 text-xs text-slate-500">
              <p className="flex items-center gap-2 font-medium text-emerald-300"><CheckCircle2 className="size-4" /> Enforced upload boundary</p>
              <p>ZIP paths, links, executable bits, binary headers, nested archives, file counts, and expanded sizes are checked before indexing.</p>
              {analysis.data?.limitations.map((value) => <p key={value}>· {value}</p>)}
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  );
}

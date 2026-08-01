import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, FolderKanban, Plus, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";

import { createProject, getProjects } from "../api/projects";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import type { WorkspaceMode } from "../types/resources";

const fieldClass =
  "h-10 w-full rounded-md border border-line bg-black/20 px-3 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-400/50";

export function ProjectsPage() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [mode, setMode] = useState<WorkspaceMode>("local_lab");
  const projects = useQuery({ queryKey: ["projects"], queryFn: ({ signal }) => getProjects(signal) });
  const create = useMutation({
    mutationFn: createProject,
    onSuccess: async () => {
      setName("");
      setDescription("");
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      toast.success("Analysis-only project created");
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    create.mutate({ name, description, mode });
  };

  return (
    <div className="mx-auto max-w-[1500px] space-y-6 p-4 sm:p-6 lg:p-8">
      <header className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-cyan-400">
            Authorized scope registry
          </p>
          <h1 className="mt-2 text-2xl font-semibold text-slate-50">Projects</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-500">
            Every workspace starts in Analysis Only mode with explicit loopback scope.
          </p>
        </div>
        <Badge tone="safe"><ShieldCheck className="size-3" /> Network disabled by default</Badge>
      </header>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section aria-label="Project list" className="space-y-3">
          {projects.isLoading ? (
            <Card><CardContent className="py-16 text-center text-sm text-slate-500">Loading projects…</CardContent></Card>
          ) : projects.data?.length ? (
            projects.data.map((project) => (
              <Link key={project.id} to={`/projects/${project.id}`} className="block">
                <Card className="transition-colors hover:border-cyan-400/25 hover:bg-white/[0.025]">
                  <CardContent className="flex items-center gap-4 p-5">
                    <div className="grid size-10 place-items-center rounded-lg border border-cyan-400/15 bg-cyan-400/[0.06]">
                      <FolderKanban className="size-5 text-cyan-300" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <h2 className="truncate font-medium text-slate-100">{project.name}</h2>
                        <Badge>{project.mode.replaceAll("_", " ")}</Badge>
                      </div>
                      <p className="mt-1 truncate text-sm text-slate-500">
                        {project.description || "No project description"}
                      </p>
                    </div>
                    <div className="hidden gap-6 text-right sm:flex">
                      <div><p className="font-mono text-sm text-slate-200">{project.workspace_count}</p><p className="text-[10px] uppercase text-slate-600">Workspaces</p></div>
                      <div><p className="font-mono text-sm text-slate-200">{project.scope_rule_count}</p><p className="text-[10px] uppercase text-slate-600">Scope rules</p></div>
                    </div>
                    <ArrowRight className="size-4 text-slate-600" />
                  </CardContent>
                </Card>
              </Link>
            ))
          ) : (
            <Card><CardContent className="py-16 text-center"><FolderKanban className="mx-auto size-8 text-slate-700" /><p className="mt-3 text-sm text-slate-400">No projects yet</p><p className="mt-1 text-xs text-slate-600">Register an authorized local, CTF, or pentest workspace.</p></CardContent></Card>
          )}
        </section>

        <Card className="h-fit xl:sticky xl:top-24">
          <CardHeader><CardTitle className="flex items-center gap-2"><Plus className="size-4 text-cyan-400" /> New project</CardTitle></CardHeader>
          <CardContent>
            <form onSubmit={submit} className="space-y-4">
              <label className="block text-xs text-slate-400">Project name<input required value={name} onChange={(event) => setName(event.target.value)} className={`${fieldClass} mt-1.5`} placeholder="Local Shop Review" /></label>
              <label className="block text-xs text-slate-400">Authorization context<select value={mode} onChange={(event) => setMode(event.target.value as WorkspaceMode)} className={`${fieldClass} mt-1.5`}><option value="local_lab">Local Lab</option><option value="ctf">CTF</option><option value="authorized_pentest">Authorized Pentest</option></select></label>
              <label className="block text-xs text-slate-400">Description<textarea value={description} onChange={(event) => setDescription(event.target.value)} className="mt-1.5 min-h-24 w-full resize-y rounded-md border border-line bg-black/20 p-3 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-400/50" placeholder="Ownership, rules of engagement, or challenge notes" /></label>
              <div className="rounded-md border border-amber-400/15 bg-amber-400/[0.04] p-3 text-xs leading-5 text-amber-200/70">External hosts require a separate authorization confirmation and scope description.</div>
              <Button type="submit" className="w-full" disabled={create.isPending || !name.trim()}>{create.isPending ? "Creating…" : "Create analysis project"}</Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

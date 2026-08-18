import { useQuery } from "@tanstack/react-query";
import { ClipboardCopy, FileText, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { getProjects } from "../api/projects";
import { getProjectReport, getProjectReportMarkdown } from "../api/reports";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import type { ReportFinding } from "../types/resources";

const fieldClass =
  "h-10 w-full rounded-md border border-line bg-black/20 px-3 text-sm text-slate-100 outline-none focus:border-cyan-400/50 sm:w-72";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function severityTone(severity: string) {
  if (severity === "critical" || severity === "high") return "critical" as const;
  if (severity === "medium") return "warning" as const;
  if (severity === "low") return "accent" as const;
  return "neutral" as const;
}

function orderedSeverities(counts: Record<string, number>) {
  const known = SEVERITY_ORDER.filter((severity) => severity in counts);
  const extra = Object.keys(counts)
    .filter((severity) => !SEVERITY_ORDER.includes(severity))
    .sort();
  return [...known, ...extra];
}

export function ReportsPage() {
  const [selected, setSelected] = useState<string>("");
  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: ({ signal }) => getProjects(signal),
  });

  // Default to the first project until the user picks another.
  const projectId = selected || projects.data?.[0]?.id || "";

  const report = useQuery({
    queryKey: ["project-report", projectId],
    queryFn: ({ signal }) => getProjectReport(projectId, signal),
    enabled: Boolean(projectId),
  });

  const copyMarkdown = async () => {
    try {
      const markdown = await getProjectReportMarkdown(projectId);
      await navigator.clipboard.writeText(markdown);
      toast.success("Report Markdown copied to clipboard");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not copy the report");
    }
  };

  const summary = report.data?.summary;

  return (
    <div className="mx-auto max-w-[1500px] space-y-6 p-4 sm:p-6 lg:p-8">
      <header className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
        <div>
          <p className="flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-cyan-300">
            <FileText className="size-4" /> Findings Report
          </p>
          <h1 className="mt-2 text-2xl font-semibold text-slate-100">
            Consolidated findings
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            Every static source-to-sink and scanner finding for a project, bundled and ranked.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            aria-label="Select project"
            className={fieldClass}
            value={projectId}
            onChange={(event) => setSelected(event.target.value)}
          >
            {(projects.data ?? []).map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>
          <Button
            variant="secondary"
            disabled={!report.data || report.data.summary.total === 0}
            onClick={() => void copyMarkdown()}
          >
            <ClipboardCopy className="size-4" /> Copy Markdown
          </Button>
        </div>
      </header>

      {projects.data && projects.data.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center text-sm text-slate-500">
            Create a project and run analysis or a scan to generate findings.
          </CardContent>
        </Card>
      ) : null}

      {summary ? (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-widest text-slate-500">
                Total findings
              </CardTitle>
            </CardHeader>
            <CardContent className="text-3xl font-semibold text-slate-100">
              {summary.total}
            </CardContent>
          </Card>
          {orderedSeverities(summary.by_severity).map((severity) => (
            <Card key={severity}>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-widest text-slate-500">
                  {severity}
                </CardTitle>
              </CardHeader>
              <CardContent className="flex items-center gap-2 text-3xl font-semibold text-slate-100">
                {summary.by_severity[severity]}
                <Badge tone={severityTone(severity)}>{severity}</Badge>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm text-slate-200">
            <ShieldAlert className="size-4 text-amber-300" /> Findings
            {summary ? (
              <Badge tone="neutral">{summary.total}</Badge>
            ) : null}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {report.isLoading ? (
            <p className="py-8 text-center text-sm text-slate-500">Loading report…</p>
          ) : report.isError ? (
            <p className="py-8 text-center text-sm text-red-400">
              The report could not be loaded.
            </p>
          ) : report.data && report.data.findings.length > 0 ? (
            <FindingsTable findings={report.data.findings} />
          ) : (
            <p className="py-8 text-center text-sm text-slate-500">
              No static or scanner findings were recorded for this project.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function FindingsTable({ findings }: { findings: ReportFinding[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-line text-[11px] uppercase tracking-widest text-slate-500">
            <th className="px-3 py-2 font-medium">Severity</th>
            <th className="px-3 py-2 font-medium">Source</th>
            <th className="px-3 py-2 font-medium">Category</th>
            <th className="px-3 py-2 font-medium">Title</th>
            <th className="px-3 py-2 font-medium">Location</th>
            <th className="px-3 py-2 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr key={`${finding.source}:${finding.origin_id}`} className="border-b border-line/50">
              <td className="px-3 py-2">
                <Badge tone={severityTone(finding.severity)}>{finding.severity}</Badge>
              </td>
              <td className="px-3 py-2">
                <Badge tone={finding.source === "scanner" ? "accent" : "neutral"}>
                  {finding.source}
                </Badge>
              </td>
              <td className="px-3 py-2 text-slate-400">{finding.category}</td>
              <td className="px-3 py-2 text-slate-200">{finding.title}</td>
              <td className="px-3 py-2 font-mono text-xs text-slate-400">{finding.location}</td>
              <td className="px-3 py-2 text-slate-400">{finding.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

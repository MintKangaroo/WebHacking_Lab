import { useQuery } from "@tanstack/react-query";
import {
  ArrowDownUp,
  ClipboardCopy,
  FileText,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { getProjects } from "../api/projects";
import {
  getProjectReport,
  getProjectReportMarkdown,
  getReportFindingDetail,
} from "../api/reports";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import type {
  ReportFinding,
  ReportFindingDetail,
  ReportSource,
} from "../types/resources";

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

function severityRank(severity: string) {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index === -1 ? SEVERITY_ORDER.length : index;
}

type SortField = "severity" | "title" | "category" | "source";

function compareFindings(a: ReportFinding, b: ReportFinding, field: SortField): number {
  if (field === "severity") return severityRank(a.severity) - severityRank(b.severity);
  return a[field].localeCompare(b[field]);
}

const selectClass =
  "h-9 rounded-md border border-line bg-black/20 px-2 text-sm text-slate-200 outline-none focus:border-cyan-400/50";

type Selection = { source: ReportSource; originId: string };

export function ReportsPage() {
  const [selected, setSelected] = useState<string>("");
  const [finding, setFinding] = useState<Selection | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [query, setQuery] = useState<string>("");
  const [sortField, setSortField] = useState<SortField>("severity");
  const [descending, setDescending] = useState<boolean>(false);
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

  const detail = useQuery({
    queryKey: ["report-finding", projectId, finding?.source, finding?.originId],
    queryFn: ({ signal }) =>
      getReportFindingDetail(projectId, finding!.source, finding!.originId, signal),
    enabled: Boolean(projectId && finding),
  });

  const allFindings = useMemo(() => report.data?.findings ?? [], [report.data?.findings]);
  const categories = useMemo(
    () => Array.from(new Set(allFindings.map((item) => item.category))).sort(),
    [allFindings],
  );

  const visibleFindings = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const filtered = allFindings.filter((item) => {
      if (severityFilter !== "all" && item.severity !== severityFilter) return false;
      if (sourceFilter !== "all" && item.source !== sourceFilter) return false;
      if (categoryFilter !== "all" && item.category !== categoryFilter) return false;
      if (
        needle &&
        !`${item.title} ${item.location} ${item.category}`.toLowerCase().includes(needle)
      ) {
        return false;
      }
      return true;
    });
    filtered.sort((a, b) => {
      const ordered = compareFindings(a, b, sortField);
      return descending ? -ordered : ordered;
    });
    return filtered;
  }, [allFindings, severityFilter, sourceFilter, categoryFilter, query, sortField, descending]);

  const changeProject = (value: string) => {
    setSelected(value);
    setFinding(null);
    setSeverityFilter("all");
    setSourceFilter("all");
    setCategoryFilter("all");
    setQuery("");
  };

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
            onChange={(event) => changeProject(event.target.value)}
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

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className={finding ? "lg:col-span-2" : "lg:col-span-3"}>
          <CardHeader className="gap-3">
            <CardTitle className="flex items-center gap-2 text-sm text-slate-200">
              <ShieldAlert className="size-4 text-amber-300" /> Findings
              {summary ? (
                <Badge tone="neutral">
                  {visibleFindings.length} / {summary.total}
                </Badge>
              ) : null}
            </CardTitle>
            {allFindings.length > 0 ? (
              <div className="flex flex-wrap items-center gap-2">
                <label className="relative">
                  <Search className="pointer-events-none absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-slate-500" />
                  <input
                    type="search"
                    aria-label="Search findings"
                    placeholder="Search title, location, category"
                    className="h-9 w-56 rounded-md border border-line bg-black/20 pl-7 pr-2 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/50"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                  />
                </label>
                <select
                  aria-label="Filter by severity"
                  className={selectClass}
                  value={severityFilter}
                  onChange={(event) => setSeverityFilter(event.target.value)}
                >
                  <option value="all">All severities</option>
                  {orderedSeverities(summary?.by_severity ?? {}).map((severity) => (
                    <option key={severity} value={severity}>
                      {severity}
                    </option>
                  ))}
                </select>
                <select
                  aria-label="Filter by source"
                  className={selectClass}
                  value={sourceFilter}
                  onChange={(event) => setSourceFilter(event.target.value)}
                >
                  <option value="all">All sources</option>
                  <option value="static">static</option>
                  <option value="scanner">scanner</option>
                </select>
                <select
                  aria-label="Filter by category"
                  className={selectClass}
                  value={categoryFilter}
                  onChange={(event) => setCategoryFilter(event.target.value)}
                >
                  <option value="all">All categories</option>
                  {categories.map((category) => (
                    <option key={category} value={category}>
                      {category}
                    </option>
                  ))}
                </select>
                <select
                  aria-label="Sort by"
                  className={selectClass}
                  value={sortField}
                  onChange={(event) => setSortField(event.target.value as SortField)}
                >
                  <option value="severity">Sort: severity</option>
                  <option value="category">Sort: category</option>
                  <option value="title">Sort: title</option>
                  <option value="source">Sort: source</option>
                </select>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label="Toggle sort direction"
                  onClick={() => setDescending((value) => !value)}
                >
                  <ArrowDownUp className="size-4" /> {descending ? "Desc" : "Asc"}
                </Button>
              </div>
            ) : null}
          </CardHeader>
          <CardContent>
            {report.isLoading ? (
              <p className="py-8 text-center text-sm text-slate-500">Loading report…</p>
            ) : report.isError ? (
              <p className="py-8 text-center text-sm text-red-400">
                The report could not be loaded.
              </p>
            ) : allFindings.length === 0 ? (
              <p className="py-8 text-center text-sm text-slate-500">
                No static or scanner findings were recorded for this project.
              </p>
            ) : visibleFindings.length === 0 ? (
              <p className="py-8 text-center text-sm text-slate-500">
                No findings match the current filters.
              </p>
            ) : (
              <FindingsTable
                findings={visibleFindings}
                selectedId={finding?.originId ?? null}
                onSelect={(row) => setFinding({ source: row.source, originId: row.origin_id })}
              />
            )}
          </CardContent>
        </Card>

        {finding ? (
          <Card className="lg:col-span-1">
            <CardHeader className="flex flex-row items-start justify-between gap-2">
              <CardTitle className="text-sm text-slate-200">Finding detail</CardTitle>
              <button
                type="button"
                aria-label="Close finding detail"
                className="text-slate-500 hover:text-slate-200"
                onClick={() => setFinding(null)}
              >
                <X className="size-4" />
              </button>
            </CardHeader>
            <CardContent>
              {detail.isLoading ? (
                <p className="py-6 text-center text-sm text-slate-500">Loading detail…</p>
              ) : detail.isError ? (
                <p className="py-6 text-center text-sm text-red-400">
                  The finding detail could not be loaded.
                </p>
              ) : detail.data ? (
                <FindingDetail
                  data={detail.data}
                />
              ) : null}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  );
}

function FindingsTable({
  findings,
  selectedId,
  onSelect,
}: {
  findings: ReportFinding[];
  selectedId: string | null;
  onSelect: (finding: ReportFinding) => void;
}) {
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
            <tr
              key={`${finding.source}:${finding.origin_id}`}
              className={`cursor-pointer border-b border-line/50 transition-colors hover:bg-white/[0.03] ${
                finding.origin_id === selectedId ? "bg-cyan-500/5" : ""
              }`}
              onClick={() => onSelect(finding)}
            >
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

function Section({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <p className="text-[11px] uppercase tracking-widest text-slate-500">{title}</p>
      <ul className="mt-1 space-y-1 text-sm text-slate-300">
        {items.map((item, index) => (
          <li key={`${title}-${index}`} className="flex gap-2">
            <span className="text-slate-600">•</span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function FindingDetail({ data }: { data: ReportFindingDetail }) {
  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-center gap-2">
          <Badge tone={severityTone(data.severity)}>{data.severity}</Badge>
          <Badge tone={data.source === "scanner" ? "accent" : "neutral"}>{data.source}</Badge>
        </div>
        <h3 className="mt-2 text-sm font-semibold text-slate-100">{data.title}</h3>
        <p className="mt-1 font-mono text-xs text-slate-400">{data.location}</p>
        <p className="mt-2 text-sm text-slate-300">{data.summary}</p>
      </div>

      {data.flow_steps.length > 0 ? (
        <div>
          <p className="text-[11px] uppercase tracking-widest text-slate-500">Data flow</p>
          <ol className="mt-1 space-y-1 text-sm">
            {data.flow_steps.map((step, index) => (
              <li key={`flow-${index}`} className="flex gap-2">
                <Badge tone={step.kind === "sink" ? "critical" : "neutral"}>{step.kind}</Badge>
                <span className="text-slate-300">
                  {step.label}
                  <span className="text-slate-600"> · line {step.line}</span>
                </span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}

      <Section title="Evidence" items={data.evidence} />
      <Section title="Remediation" items={data.remediation} />

      {data.safe_example ? (
        <div>
          <p className="text-[11px] uppercase tracking-widest text-slate-500">Safe example</p>
          <pre className="mt-1 overflow-x-auto rounded-md border border-line bg-black/30 p-3 font-mono text-xs text-slate-300">
            {data.safe_example}
          </pre>
        </div>
      ) : null}

      <Section title="Limitations" items={data.limitations} />
    </div>
  );
}

import { useQuery } from "@tanstack/react-query";
import { FlaskConical, Lightbulb, Target, TriangleAlert } from "lucide-react";

import { getLabs } from "../api/labs";
import { Badge } from "../components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import type { LabInfo } from "../types/resources";

export function LabsPage() {
  const catalog = useQuery({ queryKey: ["labs"], queryFn: ({ signal }) => getLabs(signal) });

  return (
    <div className="mx-auto max-w-[1200px] space-y-6 p-4 sm:p-6 lg:p-8">
      <header>
        <p className="flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-cyan-300">
          <FlaskConical className="size-4" /> Isolated Training Labs
        </p>
        <h1 className="mt-2 text-2xl font-semibold text-slate-100">Local labs</h1>
        <p className="mt-1 text-sm text-slate-500">
          Intentionally vulnerable targets on the internal lab network. Point the scanner or
          repeater at a lab once its host is registered in a project scope.
        </p>
      </header>

      <div className="flex items-start gap-3 rounded-md border border-amber-500/25 bg-amber-500/5 p-4 text-sm text-amber-200">
        <TriangleAlert className="mt-0.5 size-4 shrink-0" />
        <div>
          <p>{catalog.data?.warning ?? "These targets are intentionally vulnerable."}</p>
          <p className="mt-1 text-amber-300/80">
            {catalog.data?.enabled
              ? "Labs are enabled for this deployment."
              : "Start them with docker compose --profile labs up. Disabled by default."}
          </p>
        </div>
      </div>

      {catalog.isLoading ? (
        <p className="py-8 text-center text-sm text-slate-500">Loading labs…</p>
      ) : catalog.isError ? (
        <p className="py-8 text-center text-sm text-red-400">The lab catalog could not be loaded.</p>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {(catalog.data?.labs ?? []).map((lab) => (
            <LabCard key={lab.id} lab={lab} />
          ))}
        </div>
      )}
    </div>
  );
}

function LabCard({ lab }: { lab: LabInfo }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-2 text-sm text-slate-100">
          {lab.name}
          <span className="flex gap-1.5">
            <Badge tone="accent">{lab.category}</Badge>
            <Badge tone="neutral">{lab.difficulty}</Badge>
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-slate-400">{lab.description}</p>
        <p className="flex items-start gap-2 text-slate-300">
          <Target className="mt-0.5 size-4 shrink-0 text-cyan-300" />
          {lab.objective}
        </p>
        <p className="flex items-start gap-2 text-slate-400">
          <Lightbulb className="mt-0.5 size-4 shrink-0 text-amber-300" />
          {lab.hint}
        </p>
        <p className="font-mono text-xs text-slate-400">
          Target: {lab.base_url}
          {lab.target_path}
        </p>
      </CardContent>
    </Card>
  );
}

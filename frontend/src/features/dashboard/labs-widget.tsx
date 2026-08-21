import { useQuery } from "@tanstack/react-query";
import { ArrowRight, FlaskConical, Radar } from "lucide-react";
import { Link } from "react-router-dom";

import { getLabs } from "../../api/labs";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card";
import { buildLabScanSearch } from "../../utils/lab-scan";

export function LabsWidget() {
  const catalog = useQuery({
    queryKey: ["labs"],
    queryFn: ({ signal }) => getLabs(signal),
  });
  const labs = catalog.data?.labs ?? [];
  const enabled = catalog.data?.enabled ?? false;

  return (
    <Card className="min-w-0">
      <CardHeader className="flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <CardTitle className="flex items-center gap-2 text-sm text-slate-100">
            <FlaskConical className="size-4 text-cyan-300" /> Local Labs
          </CardTitle>
          {catalog.data && (
            <Badge tone={enabled ? "safe" : "neutral"}>
              {enabled ? "Running" : "Disabled"}
            </Badge>
          )}
        </div>
        <Link
          to="/labs"
          className="inline-flex items-center gap-1 text-[11px] text-slate-500 hover:text-cyan-300"
        >
          View all <ArrowRight className="size-3" />
        </Link>
      </CardHeader>
      <CardContent className="space-y-3">
        {catalog.isLoading ? (
          <p className="text-xs text-slate-500">Loading labs…</p>
        ) : catalog.isError ? (
          <p className="text-xs text-red-400">The lab catalog could not be loaded.</p>
        ) : (
          <>
            <p className="text-xs leading-5 text-slate-500">
              {labs.length} isolated training {labs.length === 1 ? "target" : "targets"}.{" "}
              {enabled
                ? "Launch a pre-filled scan against any running lab."
                : "Start them with docker compose --profile labs up to scan."}
            </p>
            <ul className="divide-y divide-line/70">
              {labs.map((lab) => (
                <li key={lab.id} className="flex items-center gap-2 py-2">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-xs font-medium text-slate-200">{lab.name}</p>
                    <p className="truncate font-mono text-[10px] text-slate-600">
                      {lab.category}
                    </p>
                  </div>
                  {enabled ? (
                    <Button asChild size="sm" variant="secondary" className="h-7 px-2 text-[11px]">
                      <Link to={`/scans${buildLabScanSearch(lab)}`}>
                        <Radar className="size-3" /> Scan
                      </Link>
                    </Button>
                  ) : (
                    <span className="text-[10px] uppercase tracking-wider text-slate-600">
                      {lab.difficulty}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  );
}

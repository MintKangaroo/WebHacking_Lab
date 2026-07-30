import {
  ArrowDownRight,
  ArrowUpRight,
  Ban,
  Bug,
  CheckCircle2,
  FolderKanban,
  ScanSearch,
} from "lucide-react";

import { Card } from "../../components/ui/card";
import type { Metric } from "../../types/dashboard";
import { cn } from "../../utils/cn";

const metricIcons = {
  "Active projects": FolderKanban,
  "Analyzed requests": ScanSearch,
  "Finding candidates": Bug,
  "Confirmed findings": CheckCircle2,
  "Scope blocks": Ban,
} as const;

export function MetricCard({ metric, index }: { metric: Metric; index: number }) {
  const Icon = metricIcons[metric.label as keyof typeof metricIcons] ?? ScanSearch;
  const TrendIcon = metric.trend === "down" ? ArrowDownRight : ArrowUpRight;

  return (
    <Card
      className="animate-fade-up overflow-hidden p-4 shadow-none"
      style={{ animationDelay: `${index * 50}ms` }}
    >
      <div className="flex items-start justify-between">
        <span className="text-[11px] font-medium uppercase tracking-[0.12em] text-slate-500">
          {metric.label}
        </span>
        <span className="grid size-7 place-items-center rounded-md bg-white/[0.035] text-slate-500">
          <Icon className="size-3.5" aria-hidden="true" />
        </span>
      </div>
      <div className="mt-4 flex items-end justify-between">
        <span className="text-2xl font-semibold tracking-tight text-slate-50">
          {metric.value.toLocaleString()}
        </span>
        {metric.delta === null ? (
          <span className="text-[10px] text-slate-600">policy events</span>
        ) : (
          <span
            className={cn(
              "inline-flex items-center text-[10px]",
              metric.trend === "up" ? "text-emerald-400" : "text-slate-500",
            )}
          >
            <TrendIcon className="mr-0.5 size-3" />
            {Math.abs(metric.delta)}%
          </span>
        )}
      </div>
    </Card>
  );
}

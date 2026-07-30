import { useSuspenseQuery } from "@tanstack/react-query";
import {
  ArrowRight,
  FlaskConical,
  Plus,
  RadioTower,
  ShieldCheck,
} from "lucide-react";
import { Suspense } from "react";

import { dashboardQueryOptions } from "../api/dashboard";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { ActivityFeed } from "../features/dashboard/activity-feed";
import {
  AnalysisTypesChart,
  RequestVolumeChart,
  SeverityChart,
} from "../features/dashboard/dashboard-charts";
import { DashboardSkeleton } from "../features/dashboard/dashboard-skeleton";
import { MetricCard } from "../features/dashboard/metric-card";
import { SafetyPanel } from "../features/dashboard/safety-panel";

function DashboardContent() {
  const { data } = useSuspenseQuery(dashboardQueryOptions());

  return (
    <div className="mx-auto max-w-[1600px] space-y-6 p-4 sm:p-6 lg:p-8">
      <section className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-400">
              Operations overview
            </span>
            {data.demo_mode && <Badge>Demonstration data</Badge>}
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-50 sm:text-3xl">
            Security analysis, under control.
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-slate-500">
            Review evidence, scope decisions, and learning progress from one
            safety-first workspace. Active testing remains off until explicitly approved.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" disabled>
            <FlaskConical className="size-4" />
            Start local lab
          </Button>
          <Button disabled>
            <Plus className="size-4" />
            New project
          </Button>
        </div>
      </section>

      <section
        aria-label="Safety mode"
        className="flex flex-col gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/[0.045] px-4 py-3 sm:flex-row sm:items-center"
      >
        <div className="grid size-8 shrink-0 place-items-center rounded-lg bg-emerald-400/10">
          <ShieldCheck className="size-4 text-emerald-300" aria-hidden="true" />
        </div>
        <div className="min-w-0">
          <p className="text-xs font-medium text-emerald-200">
            Analysis Only mode is enforced
          </p>
          <p className="mt-0.5 text-[11px] text-emerald-200/50">
            Network execution is disabled. All visible activity is sanitized demo or local
            workspace data.
          </p>
        </div>
        <Badge tone="safe" className="w-fit sm:ml-auto">
          <RadioTower className="size-2.5" />
          No outbound requests
        </Badge>
      </section>

      <section aria-label="Workspace metrics" className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {data.metrics.map((metric, index) => (
          <MetricCard key={metric.label} metric={metric} index={index} />
        ))}
      </section>

      <section aria-label="Request and severity charts" className="grid gap-4 xl:grid-cols-3">
        <RequestVolumeChart data={data.request_volume} />
        <SeverityChart data={data.severity_distribution} />
      </section>

      <section aria-label="Analysis operations" className="grid gap-4 xl:grid-cols-4">
        <ActivityFeed items={data.recent_activity} />
        <AnalysisTypesChart data={data.analysis_types} />
        <SafetyPanel safety={data.safety} />
      </section>

      <footer className="flex flex-col gap-2 border-t border-line py-3 text-[10px] text-slate-600 sm:flex-row sm:items-center">
        <span>WebHacking Lab v0.1.0 · Foundation</span>
        <span className="hidden sm:inline">•</span>
        <span>For authorized testing, CTF, and isolated local labs only</span>
        <a
          href="/api/docs"
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1 text-slate-500 hover:text-cyan-300 sm:ml-auto"
        >
          API reference <ArrowRight className="size-3" />
        </a>
      </footer>
    </div>
  );
}

export function DashboardPage() {
  return (
    <Suspense fallback={<DashboardSkeleton />}>
      <DashboardContent />
    </Suspense>
  );
}

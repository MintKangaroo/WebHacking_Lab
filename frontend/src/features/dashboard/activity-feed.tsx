import {
  Ban,
  BookOpenText,
  Bug,
  Check,
  FlaskConical,
  ScanSearch,
} from "lucide-react";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "../../components/ui/card";
import type { RecentActivity } from "../../types/dashboard";

const activityIcons = {
  analysis: ScanSearch,
  finding: Bug,
  scope: Ban,
  ctf: BookOpenText,
  lab: FlaskConical,
} as const;

const activityColors: Record<RecentActivity["status"], string> = {
  completed: "bg-emerald-400",
  review: "bg-amber-400",
  blocked: "bg-red-400",
  active: "bg-cyan-400",
};

export function ActivityFeed({ items }: { items: RecentActivity[] }) {
  return (
    <Card className="min-w-0 xl:col-span-2">
      <CardHeader className="flex-row items-center justify-between">
        <div>
          <CardTitle>Recent activity</CardTitle>
          <p className="mt-1 text-xs text-slate-500">
            Sanitized events from analysis and audit streams
          </p>
        </div>
        <Check className="size-4 text-emerald-400" aria-label="Feed synchronized" />
      </CardHeader>
      <CardContent>
        <ol className="divide-y divide-line/70">
          {items.map((item) => {
            const Icon = activityIcons[item.kind];
            return (
              <li key={item.id} className="flex gap-3 py-3 first:pt-0 last:pb-0">
                <div className="relative mt-0.5 grid size-8 shrink-0 place-items-center rounded-lg border border-line bg-white/[0.025] text-slate-500">
                  <Icon className="size-3.5" aria-hidden="true" />
                  <span
                    className={`absolute -right-0.5 -top-0.5 size-2 rounded-full border-2 border-panel ${activityColors[item.status]}`}
                  />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-3">
                    <p className="truncate text-xs font-medium text-slate-200">
                      {item.title}
                    </p>
                    <time className="ml-auto shrink-0 text-[10px] text-slate-600">
                      {item.occurred_at}
                    </time>
                  </div>
                  <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-slate-500">
                    {item.detail}
                  </p>
                </div>
              </li>
            );
          })}
        </ol>
      </CardContent>
    </Card>
  );
}

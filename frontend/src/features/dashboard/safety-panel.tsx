import {
  CheckCircle2,
  LockKeyhole,
  Network,
  ShieldCheck,
} from "lucide-react";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "../../components/ui/card";
import type { SafetyStatus } from "../../types/dashboard";

export function SafetyPanel({ safety }: { safety: SafetyStatus }) {
  const rules = [
    {
      label: "Execution",
      value: safety.network_execution_enabled ? "Enabled" : "Disabled",
      icon: Network,
    },
    {
      label: "TLS bypass",
      value: safety.insecure_tls_allowed ? "Enabled" : "Blocked",
      icon: LockKeyhole,
    },
    {
      label: "Global budget",
      value: `${safety.global_requests_per_minute} req/min`,
      icon: ShieldCheck,
    },
    {
      label: "Response cap",
      value: `${(safety.max_response_bytes / 1024 / 1024).toFixed(0)} MiB`,
      icon: CheckCircle2,
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Safety controls</CardTitle>
        <p className="mt-1 text-xs text-slate-500">Effective backend policy</p>
      </CardHeader>
      <CardContent className="space-y-2.5">
        {rules.map((rule) => (
          <div
            key={rule.label}
            className="flex items-center gap-3 rounded-lg border border-line/70 bg-black/10 px-3 py-2.5"
          >
            <rule.icon className="size-3.5 text-emerald-400" aria-hidden="true" />
            <span className="text-[11px] text-slate-500">{rule.label}</span>
            <span className="ml-auto font-mono text-[10px] text-slate-300">
              {rule.value}
            </span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

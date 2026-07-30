import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "../../components/ui/card";
import type {
  AnalysisTypeDatum,
  RequestVolumeDatum,
  SeverityDatum,
} from "../../types/dashboard";

const severityColors: Record<SeverityDatum["severity"], string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#f59e0b",
  Low: "#22d3ee",
  Info: "#64748b",
};

const tooltipStyle = {
  background: "#0f1720",
  border: "1px solid #263342",
  borderRadius: "8px",
  color: "#cbd5e1",
  fontSize: "12px",
};

export function RequestVolumeChart({ data }: { data: RequestVolumeDatum[] }) {
  return (
    <Card className="min-w-0 xl:col-span-2">
      <CardHeader className="flex-row items-start justify-between">
        <div>
          <CardTitle>Request activity</CardTitle>
          <p className="mt-1 text-xs text-slate-500">
            Controlled requests and policy blocks by hour
          </p>
        </div>
        <span className="rounded-md border border-line px-2 py-1 text-[10px] text-slate-500">
          Demo · 7 hours
        </span>
      </CardHeader>
      <CardContent className="h-[245px] pl-1">
        <ResponsiveContainer
          width="100%"
          height="100%"
          initialDimension={{ width: 800, height: 245 }}
        >
          <AreaChart data={data} margin={{ top: 8, right: 16, bottom: 0, left: -18 }}>
            <defs>
              <linearGradient id="requestFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.22} />
                <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1c2631" strokeDasharray="3 4" vertical={false} />
            <XAxis
              dataKey="label"
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#64748b", fontSize: 10 }}
              dy={8}
            />
            <YAxis
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#64748b", fontSize: 10 }}
            />
            <ChartTooltip contentStyle={tooltipStyle} />
            <Area
              type="monotone"
              dataKey="requests"
              stroke="#22d3ee"
              strokeWidth={2}
              fill="url(#requestFill)"
            />
            <Area
              type="monotone"
              dataKey="blocked"
              stroke="#f59e0b"
              strokeWidth={1.5}
              fill="transparent"
            />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

export function SeverityChart({ data }: { data: SeverityDatum[] }) {
  const total = data.reduce((sum, item) => sum + item.count, 0);

  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle>Severity posture</CardTitle>
        <p className="mt-1 text-xs text-slate-500">Open observations and findings</p>
      </CardHeader>
      <CardContent className="grid grid-cols-[145px_1fr] items-center gap-2">
        <div className="relative h-[170px]">
          <ResponsiveContainer
            width="100%"
            height="100%"
            initialDimension={{ width: 145, height: 170 }}
          >
            <PieChart>
              <Pie
                data={data}
                dataKey="count"
                nameKey="severity"
                innerRadius={48}
                outerRadius={66}
                paddingAngle={3}
                stroke="none"
              >
                {data.map((item) => (
                  <Cell key={item.severity} fill={severityColors[item.severity]} />
                ))}
              </Pie>
              <ChartTooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
            <span className="text-2xl font-semibold text-slate-100">{total}</span>
            <span className="text-[9px] uppercase tracking-wider text-slate-600">
              total
            </span>
          </div>
        </div>
        <ul className="space-y-2">
          {data.map((item) => (
            <li key={item.severity} className="flex items-center text-[11px]">
              <span
                className="mr-2 size-1.5 rounded-full"
                style={{ backgroundColor: severityColors[item.severity] }}
              />
              <span className="text-slate-500">{item.severity}</span>
              <span className="ml-auto font-mono text-slate-300">{item.count}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

export function AnalysisTypesChart({ data }: { data: AnalysisTypeDatum[] }) {
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle>Analysis coverage</CardTitle>
        <p className="mt-1 text-xs text-slate-500">Checks grouped by analyzer family</p>
      </CardHeader>
      <CardContent className="h-[218px] pl-0">
        <ResponsiveContainer
          width="100%"
          height="100%"
          initialDimension={{ width: 320, height: 218 }}
        >
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 0, right: 14, bottom: 0, left: 8 }}
          >
            <CartesianGrid stroke="#1c2631" strokeDasharray="3 4" horizontal={false} />
            <XAxis
              type="number"
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#64748b", fontSize: 10 }}
            />
            <YAxis
              type="category"
              dataKey="category"
              width={68}
              axisLine={false}
              tickLine={false}
              tick={{ fill: "#94a3b8", fontSize: 10 }}
            />
            <ChartTooltip contentStyle={tooltipStyle} cursor={{ fill: "#ffffff05" }} />
            <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} barSize={8} />
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

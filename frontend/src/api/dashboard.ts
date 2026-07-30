import { queryOptions } from "@tanstack/react-query";

import { apiGet } from "./client";
import type { DashboardOverview } from "../types/dashboard";

export function dashboardQueryOptions() {
  return queryOptions({
    queryKey: ["dashboard", "overview"],
    queryFn: ({ signal }) => apiGet<DashboardOverview>("/dashboard/overview", signal),
    staleTime: 30_000,
  });
}

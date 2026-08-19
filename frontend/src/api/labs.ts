import { apiGet } from "./client";
import type { LabCatalog } from "../types/resources";

export function getLabs(signal?: AbortSignal) {
  return apiGet<LabCatalog>("/labs", signal);
}

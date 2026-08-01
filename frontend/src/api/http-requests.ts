import { apiJson } from "./client";
import type { ImportResult, NameValue, NormalizedRequest } from "../types/resources";

export function importCurl(input: {
  command: string;
  workspace_id?: string;
  persist: boolean;
}) {
  return apiJson<ImportResult, typeof input>("/requests/import/curl", "POST", input);
}

export function importHar(input: {
  content: string;
  workspace_id?: string;
  persist: boolean;
}) {
  return apiJson<ImportResult, typeof input>("/requests/import/har", "POST", input);
}

export function storeRequest(input: {
  workspace_id: string;
  method: string;
  url: string;
  headers: Array<Omit<NameValue, "redacted">>;
  body: string;
}) {
  return apiJson<{ normalized: NormalizedRequest }, typeof input>(
    "/requests",
    "POST",
    input,
  );
}

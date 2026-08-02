import { apiGet, apiJson } from "./client";
import type {
  HttpRequestRecord,
  ImportResult,
  NameValue,
  RequestExecutionPreview,
  RequestExecutionResult,
} from "../types/resources";

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
  return apiJson<HttpRequestRecord, typeof input>(
    "/requests",
    "POST",
    input,
  );
}

export function getRequest(requestId: string, signal?: AbortSignal) {
  return apiGet<HttpRequestRecord>(`/requests/${requestId}`, signal);
}

export function previewRequestExecution(requestId: string) {
  return apiJson<RequestExecutionPreview>(
    `/requests/${requestId}/execute/preview`,
    "POST",
  );
}

export function executeRequest(
  requestId: string,
  input: {
    confirmation_phrase: "SEND UP TO 5 SAFE REQUESTS";
    approval_token: string;
    request_version: number;
  },
) {
  return apiJson<RequestExecutionResult, typeof input>(
    `/requests/${requestId}/execute`,
    "POST",
    input,
  );
}

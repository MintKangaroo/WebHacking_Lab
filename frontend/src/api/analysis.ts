import { apiJson } from "./client";
import type { AnalysisRun, ResponseDiff } from "../types/resources";

export function runAnalysis(requestId: string, responseId?: string) {
  const input = {
    request_id: requestId,
    ...(responseId ? { response_id: responseId } : {}),
  };
  return apiJson<AnalysisRun, typeof input>("/analysis", "POST", input);
}

export function compareResponses(baselineResponseId: string, testResponseId: string) {
  const input = {
    baseline_response_id: baselineResponseId,
    test_response_id: testResponseId,
  };
  return apiJson<
    { baseline_response_id: string; test_response_id: string; result: ResponseDiff },
    typeof input
  >("/diff", "POST", input);
}

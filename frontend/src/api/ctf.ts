import { apiGet, apiJson } from "./client";
import type {
  CtfChallenge,
  CtfChallengeCreate,
  CtfChallengePatch,
} from "../types/resources";

export function getChallenges(event?: string, signal?: AbortSignal) {
  const query = event ? `?event=${encodeURIComponent(event)}` : "";
  return apiGet<CtfChallenge[]>(`/ctf/challenges${query}`, signal);
}

export function createChallenge(input: CtfChallengeCreate) {
  return apiJson<CtfChallenge, CtfChallengeCreate>("/ctf/challenges", "POST", input);
}

export function updateChallenge(id: string, input: CtfChallengePatch) {
  return apiJson<CtfChallenge, CtfChallengePatch>(`/ctf/challenges/${id}`, "PATCH", input);
}

export function deleteChallenge(id: string) {
  return apiJson<void>(`/ctf/challenges/${id}`, "DELETE");
}

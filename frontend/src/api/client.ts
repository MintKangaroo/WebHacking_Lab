const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

export class ApiError extends Error {
  public readonly status: number;

  public constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function apiGet<T>(
  path: string,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "GET",
    headers: { Accept: "application/json" },
    signal,
  });

  if (!response.ok) {
    throw new ApiError(`API request failed with status ${response.status}`, response.status);
  }

  return (await response.json()) as T;
}

export async function apiGetText(
  path: string,
  signal?: AbortSignal,
): Promise<string> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "GET",
    headers: { Accept: "text/plain, text/markdown" },
    signal,
  });

  if (!response.ok) {
    throw new ApiError(`API request failed with status ${response.status}`, response.status);
  }

  return await response.text();
}

type JsonMethod = "POST" | "PATCH" | "DELETE";

export async function apiJson<TResponse, TBody = unknown>(
  path: string,
  method: JsonMethod,
  body?: TBody,
  signal?: AbortSignal,
): Promise<TResponse> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers: {
      Accept: "application/json",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });

  if (!response.ok) {
    let message = `API request failed with status ${response.status}`;
    try {
      const payload = (await response.json()) as { message?: string };
      if (payload.message) message = payload.message;
    } catch {
      // Preserve the stable fallback when an upstream response is not JSON.
    }
    throw new ApiError(message, response.status);
  }

  if (response.status === 204) return undefined as TResponse;
  return (await response.json()) as TResponse;
}

export async function apiForm<TResponse>(
  path: string,
  body: FormData,
  signal?: AbortSignal,
): Promise<TResponse> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: { Accept: "application/json" },
    body,
    signal,
  });
  if (!response.ok) {
    let message = `API request failed with status ${response.status}`;
    try {
      const payload = (await response.json()) as { message?: string };
      if (payload.message) message = payload.message;
    } catch {
      // Keep the stable fallback for a non-JSON proxy response.
    }
    throw new ApiError(message, response.status);
  }
  return (await response.json()) as TResponse;
}

import createClient from "openapi-fetch";
import type { paths } from "./schemas";

export type { paths };

export type QuickexClient = ReturnType<typeof createClient<paths>>;

export interface QuickexClientOptions {
  baseUrl: string;
  headers?: HeadersInit;
  fetch?: typeof globalThis.fetch;
}

export function createQuickexClient(options: QuickexClientOptions) {
  return createClient<paths>({
    baseUrl: options.baseUrl.replace(/\/$/, ""),
    headers: options.headers,
    fetch: options.fetch,
  });
}

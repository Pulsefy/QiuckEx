import createClient from "openapi-fetch";
import type { paths } from "./schemas";
export type { paths };
export type QuickexClient = ReturnType<typeof createClient<paths>>;
export interface QuickexClientOptions {
    baseUrl: string;
    headers?: HeadersInit;
    fetch?: typeof globalThis.fetch;
}
export declare function createQuickexClient(options: QuickexClientOptions): import("openapi-fetch").Client<paths, `${string}/${string}`>;

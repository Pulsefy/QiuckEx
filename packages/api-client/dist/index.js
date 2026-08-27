import createClient from "openapi-fetch";
export function createQuickexClient(options) {
    return createClient({
        baseUrl: options.baseUrl.replace(/\/$/, ""),
        headers: options.headers,
        fetch: options.fetch,
    });
}

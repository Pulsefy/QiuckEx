/**
 * Tests for transaction deep-link parsing logic.
 * The parseTransactionDeepLink function is defined in app/_layout.tsx,
 * so we duplicate its implementation here for isolated unit testing.
 */

const QUICKEX_HOSTS = ["quickex.to", "www.quickex.to"];
const QUICKEX_SCHEME = "quickex";

function parseTransactionDeepLink(
    raw: string,
): { id: string; params: Record<string, string> } | null {
    try {
        const url = new URL(raw);

        if (url.protocol === `${QUICKEX_SCHEME}:`) {
            const segments = url.pathname
                .replace(/^\/+/, "")
                .split("/")
                .filter(Boolean);
            if (segments.length >= 2 && segments[0] === "transaction") {
                const id = segments[1];
                const params: Record<string, string> = {};
                url.searchParams.forEach((value, key) => {
                    params[key] = value;
                });
                return { id, params };
            }
        }

        if (
            (url.protocol === "https:" || url.protocol === "http:") &&
            QUICKEX_HOSTS.includes(url.hostname)
        ) {
            const segments = url.pathname
                .replace(/^\/+/, "")
                .split("/")
                .filter(Boolean);
            if (segments.length >= 2 && segments[0] === "transaction") {
                const id = segments[1];
                const params: Record<string, string> = {};
                url.searchParams.forEach((value, key) => {
                    params[key] = value;
                });
                return { id, params };
            }
        }
    } catch {
        // ignore invalid URLs
    }
    return null;
}

describe("parseTransactionDeepLink", () => {
    it("parses quickex://transaction/:id scheme", () => {
        const result = parseTransactionDeepLink("quickex://transaction/12345");
        expect(result).toEqual({ id: "12345", params: {} });
    });

    it("parses quickex://transaction/:id with query params", () => {
        const result = parseTransactionDeepLink(
            "quickex://transaction/12345?amount=100&asset=XLM&status=Success",
        );
        expect(result).toEqual({
            id: "12345",
            params: { amount: "100", asset: "XLM", status: "Success" },
        });
    });

    it("parses https://quickex.to/transaction/:id", () => {
        const result = parseTransactionDeepLink(
            "https://quickex.to/transaction/abc-def",
        );
        expect(result).toEqual({ id: "abc-def", params: {} });
    });

    it("parses https://www.quickex.to/transaction/:id with query params", () => {
        const result = parseTransactionDeepLink(
            "https://www.quickex.to/transaction/999?memo=hello&txHash=0xabc",
        );
        expect(result).toEqual({
            id: "999",
            params: { memo: "hello", txHash: "0xabc" },
        });
    });

    it("returns null for non-transaction paths", () => {
        const result = parseTransactionDeepLink("quickex://payment/alice");
        expect(result).toBeNull();
    });

    it("returns null for unrelated hosts", () => {
        const result = parseTransactionDeepLink(
            "https://example.com/transaction/123",
        );
        expect(result).toBeNull();
    });

    it("returns null for invalid URLs", () => {
        const result = parseTransactionDeepLink("not-a-url");
        expect(result).toBeNull();
    });
});

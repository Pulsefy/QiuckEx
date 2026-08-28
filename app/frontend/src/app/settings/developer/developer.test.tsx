// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import DeveloperSettings from "./page";

vi.mock("@/lib/api", () => ({ getQuickexApiBase: () => "http://test.local" }));

const clipboardWrite = vi.fn().mockResolvedValue(undefined);
Object.defineProperty(globalThis, "navigator", {
  value: { clipboard: { writeText: clipboardWrite } },
  writable: true,
});

const existingKey = {
  id: "k1",
  name: "Existing Key",
  key_prefix: "qx_live_abc123",
  scopes: ["links:read"],
  is_active: true,
  request_count: 3,
  monthly_quota: 1000,
  last_used_at: null,
  created_at: "2026-01-01T00:00:00Z",
};

const usage = { total_keys: 1, total_requests: 3, quota: 1000 };

function jsonRes(body: unknown, ok = true, status = 200) {
  return Promise.resolve({ ok, status, json: () => Promise.resolve(body) });
}

type Routes = Record<string, (init?: RequestInit) => Promise<unknown>>;

function installFetch(routes: Routes) {
  global.fetch = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : String(input);
    const path = url.replace("http://test.local", "");
    const method = (init?.method ?? "GET").toUpperCase();
    const handler = routes[`${method} ${path}`];
    if (!handler) {
      return jsonRes({ message: `unhandled ${method} ${path}` }, false, 404);
    }
    return handler(init);
  }) as unknown as typeof fetch;
}

beforeEach(() => {
  clipboardWrite.mockClear();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("DeveloperSettings API key management (FE-68)", () => {
  it("shows only the prefix for existing keys, not a full secret", async () => {
    installFetch({
      "GET /api-keys": () => jsonRes([existingKey]),
      "GET /api-keys/usage": () => jsonRes(usage),
    });
    render(<DeveloperSettings />);

    await waitFor(() => expect(screen.getByText("Existing Key")).toBeTruthy());
    // A masked/reveal affordance exists; the full secret is never present.
    expect(screen.getByRole("button", { name: /reveal/i })).toBeTruthy();
    expect(screen.queryByText(/won't be shown again|won.t be shown again/i)).toBeNull();
  });

  it("creates a key and reveals the secret exactly once with a warning", async () => {
    const created = {
      id: "k2",
      name: "CI Bot",
      key_prefix: "qx_live_new999",
      scopes: ["links:read"],
      is_active: true,
      request_count: 0,
      monthly_quota: 1000,
      last_used_at: null,
      created_at: "2026-02-01T00:00:00Z",
      key: "qx_live_new999_FULLSECRETVALUE",
    };
    installFetch({
      "GET /api-keys": () => jsonRes([]),
      "GET /api-keys/usage": () => jsonRes({ total_keys: 0, total_requests: 0, quota: 1000 }),
      "POST /api-keys": () => jsonRes(created),
    });
    render(<DeveloperSettings />);

    await waitFor(() =>
      expect(screen.getByText(/no api keys yet/i)).toBeTruthy(),
    );

    fireEvent.click(screen.getByRole("button", { name: /create new key/i }));
    fireEvent.change(screen.getByPlaceholderText(/production app/i), {
      target: { value: "CI Bot" },
    });
    fireEvent.click(screen.getByRole("button", { name: /links:read/i }));
    fireEvent.click(screen.getByRole("button", { name: /generate key/i }));

    // One-time reveal: the full secret and the "won't be shown again" warning.
    await waitFor(() =>
      expect(screen.getByText("qx_live_new999_FULLSECRETVALUE")).toBeTruthy(),
    );
    expect(screen.getByText(/won.t be shown again/i)).toBeTruthy();

    // Copy affordance writes the raw secret. Scope to the key's action row via
    // its unique Rotate button so we don't match a sample-request copy button.
    const actionRow = screen
      .getByRole("button", { name: /rotate/i })
      .closest("div") as HTMLElement;
    fireEvent.click(within(actionRow).getByRole("button", { name: /copy/i }));
    expect(clipboardWrite).toHaveBeenCalledWith("qx_live_new999_FULLSECRETVALUE");
  });

  it("revokes a key after explicit confirmation", async () => {
    const deleteCalls: string[] = [];
    installFetch({
      "GET /api-keys": () => jsonRes([existingKey]),
      "GET /api-keys/usage": () => jsonRes(usage),
      "DELETE /api-keys/k1": () => {
        deleteCalls.push("k1");
        return jsonRes({});
      },
    });
    render(<DeveloperSettings />);

    await waitFor(() => expect(screen.getByText("Existing Key")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: /^revoke$/i }));
    // Confirmation is required before the destructive call.
    fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

    await waitFor(() => expect(deleteCalls).toEqual(["k1"]));
    await waitFor(() => expect(screen.queryByText("Existing Key")).toBeNull());
  });

  it("surfaces a backend error when revocation fails", async () => {
    installFetch({
      "GET /api-keys": () => jsonRes([existingKey]),
      "GET /api-keys/usage": () => jsonRes(usage),
      "DELETE /api-keys/k1": () =>
        jsonRes({ message: "Key is locked by admin" }, false, 409),
    });
    render(<DeveloperSettings />);

    await waitFor(() => expect(screen.getByText("Existing Key")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: /^revoke$/i }));
    fireEvent.click(screen.getByRole("button", { name: /confirm/i }));

    await waitFor(() =>
      expect(screen.getByText(/key is locked by admin/i)).toBeTruthy(),
    );
  });
});

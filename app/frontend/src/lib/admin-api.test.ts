import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AdminCredentialError, adminFetch, getAdminCredential } from "./admin-api";

describe("adminFetch", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true });
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.unstubAllEnvs();
  });

  it("attaches the admin credential to GET requests", async () => {
    vi.stubEnv("NEXT_PUBLIC_ADMIN_API_KEY", "test-admin-key");

    await adminFetch("http://localhost:4000/admin/feature-flags");

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("http://localhost:4000/admin/feature-flags");
    expect(new Headers(init?.headers).get("x-api-key")).toBe("test-admin-key");
  });

  it("attaches the admin credential to PATCH requests", async () => {
    vi.stubEnv("NEXT_PUBLIC_ADMIN_API_KEY", "test-admin-key");

    await adminFetch("http://localhost:4000/admin/feature-flags/bulk_invoicing_v2", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: true }),
    });

    const [, init] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get("x-api-key")).toBe("test-admin-key");
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("does not send the client-supplied x-admin-actor header", async () => {
    vi.stubEnv("NEXT_PUBLIC_ADMIN_API_KEY", "test-admin-key");

    await adminFetch("http://localhost:4000/admin/audit");

    const [, init] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(new Headers(init?.headers).get("x-admin-actor")).toBeNull();
  });

  it("fails loudly and does not call fetch when no credential is configured", async () => {
    vi.stubEnv("NEXT_PUBLIC_ADMIN_API_KEY", "");

    expect(getAdminCredential()).toBeNull();
    await expect(
      adminFetch("http://localhost:4000/admin/audit"),
    ).rejects.toBeInstanceOf(AdminCredentialError);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

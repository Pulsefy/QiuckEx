// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkIsAdmin, getAdminCredentialClient } from "./admin-auth";

describe("admin-auth (Real Admin Authentication)", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
    window.sessionStorage.clear();
    document.cookie.split(";").forEach((c) => {
      document.cookie = c
        .replace(/^ +/, "")
        .replace(/=.*/, `=;expires=${new Date(0).toUTCString()};path=/`);
    });
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("returns false and no credential when unauthenticated", () => {
    delete process.env.NEXT_PUBLIC_ADMIN_API_KEY;
    delete process.env.ADMIN_API_KEY;

    expect(getAdminCredentialClient()).toBeNull();
    expect(checkIsAdmin()).toBe(false);
  });

  it("reads real session/auth credential from sessionStorage or cookies", () => {
    delete process.env.NEXT_PUBLIC_ADMIN_API_KEY;

    // Test sessionStorage admin session
    window.sessionStorage.setItem("quickex.adminSession", "qk_live_test_admin_jwt_token");
    expect(getAdminCredentialClient()).toBe("qk_live_test_admin_jwt_token");
    expect(checkIsAdmin()).toBe(true);

    window.sessionStorage.clear();

    // Test cookie admin_token
    document.cookie = "admin_token=secret_admin_cookie_value";
    expect(getAdminCredentialClient()).toBe("secret_admin_cookie_value");
    expect(checkIsAdmin()).toBe(true);
  });

  it("works across both preview and production runtime configs", () => {
    // Preview runtime config
    process.env.NEXT_PUBLIC_VERCEL_ENV = "preview";
    document.cookie = "quickex.adminSession=preview_admin_token";
    expect(checkIsAdmin()).toBe(true);

    // Clear cookie
    document.cookie = "quickex.adminSession=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/";

    // Production runtime config
    process.env.NEXT_PUBLIC_VERCEL_ENV = "production";
    document.cookie = "quickex.adminSession=prod_admin_token";
    expect(checkIsAdmin()).toBe(true);

    // Unauthenticated in production runtime config
    document.cookie = "quickex.adminSession=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/";
    delete process.env.NEXT_PUBLIC_ADMIN_API_KEY;
    delete process.env.ADMIN_API_KEY;
    expect(checkIsAdmin()).toBe(false);
  });
});

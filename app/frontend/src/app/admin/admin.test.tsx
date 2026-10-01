// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import AdminLayout from "./layout";

const redirectMock = vi.fn();
vi.mock("next/navigation", () => ({
  redirect: (url: string) => {
    redirectMock(url);
    throw new Error(`Redirected to ${url}`);
  },
}));

describe("AdminLayout (Authentication & Redirection)", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
    window.sessionStorage.clear();
    document.cookie = "";
    redirectMock.mockClear();
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("redirects unauthenticated / non-admin users away from /admin/* routes in preview runtime config", () => {
    process.env.NEXT_PUBLIC_VERCEL_ENV = "preview";
    delete process.env.NEXT_PUBLIC_ADMIN_API_KEY;

    expect(() => {
      render(
        <AdminLayout>
          <div>Admin Content</div>
        </AdminLayout>,
      );
    }).toThrow("Redirected to /");

    expect(redirectMock).toHaveBeenCalledWith("/");
  });

  it("redirects unauthenticated / non-admin users away from /admin/* routes in production runtime config", () => {
    process.env.NEXT_PUBLIC_VERCEL_ENV = "production";
    delete process.env.NEXT_PUBLIC_ADMIN_API_KEY;

    expect(() => {
      render(
        <AdminLayout>
          <div>Admin Content</div>
        </AdminLayout>,
      );
    }).toThrow("Redirected to /");

    expect(redirectMock).toHaveBeenCalledWith("/");
  });

  it("renders admin console when valid admin session/credential is present", () => {
    document.cookie = "admin_token=valid_admin_session_jwt";

    render(
      <AdminLayout>
        <div>Admin Console Body</div>
      </AdminLayout>,
    );

    expect(screen.getByText("Admin Console Body")).toBeDefined();
    expect(screen.getByText("Admin Console")).toBeDefined();
    expect(redirectMock).not.toHaveBeenCalled();
  });
});

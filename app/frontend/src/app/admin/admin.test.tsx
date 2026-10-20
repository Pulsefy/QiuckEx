/**
 * AdminLayout is an async server component. @testing-library/react cannot
 * render async components as JSX (React's client renderer doesn't await them),
 * so we call the component as a plain async function, await the returned
 * element tree, and render that synchronously.
 *
 * next/navigation's redirect() throws a NEXT_REDIRECT error in production,
 * which halts the function. The mock throws too, so the "protected" JSX after
 * the redirect is never reached for non-admins, exactly like production.
 */
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

const { redirectMock, checkIsAdminMock } = vi.hoisted(() => ({
  redirectMock: vi.fn((url: string): never => {
    throw new Error(`NEXT_REDIRECT:${url}`);
  }),
  checkIsAdminMock: vi.fn<() => Promise<boolean>>(),
}));

vi.mock("next/navigation", () => ({
  redirect: redirectMock,
}));

vi.mock("@/lib/admin-auth", () => ({
  checkIsAdmin: checkIsAdminMock,
}));

import AdminLayout from "./layout";

describe("AdminLayout auth gate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  it("redirects non-admin users to / and never renders the console", async () => {
    checkIsAdminMock.mockResolvedValue(false);

    await expect(
      AdminLayout({ children: <div>secret-admin-content</div> })
    ).rejects.toThrow("NEXT_REDIRECT:/");

    expect(checkIsAdminMock).toHaveBeenCalledTimes(1);
    expect(redirectMock).toHaveBeenCalledTimes(1);
    expect(redirectMock).toHaveBeenCalledWith("/");
  });

  it("redirects when the admin check rejects (fails closed is not assumed)", async () => {
    // checkIsAdmin throwing must NOT render the admin console.
    checkIsAdminMock.mockRejectedValue(new Error("auth backend unavailable"));

    await expect(
      AdminLayout({ children: <div>secret-admin-content</div> })
    ).rejects.toThrow();

    expect(redirectMock).not.toHaveBeenCalledWith("/admin");
  });

  it("renders the admin console and children for valid admins", async () => {
    checkIsAdminMock.mockResolvedValue(true);

    const ui = await AdminLayout({ children: <div>admin-page-content</div> });
    render(ui);

    expect(redirectMock).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "Admin Console" })).toBeTruthy();
    expect(screen.getByText("Admin Active")).toBeTruthy();
    expect(screen.getByText("admin-page-content")).toBeTruthy();
  });
});
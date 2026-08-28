// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearFormDraft,
  isAuthFailure,
  loadFormDraft,
  notifyAuthExpired,
  onAuthExpired,
  resetAuthListeners,
  saveFormDraft,
  saveOriginRoute,
  takeOriginRoute,
} from "./auth-session";
import { fetchWithAuth } from "./api";

beforeEach(() => {
  resetAuthListeners();
  window.sessionStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("auth-session core (FE-70)", () => {
  it("classifies 401/403 as auth failures", () => {
    expect(isAuthFailure(401)).toBe(true);
    expect(isAuthFailure(403)).toBe(true);
    expect(isAuthFailure(200)).toBe(false);
    expect(isAuthFailure(500)).toBe(false);
  });

  it("notifies subscribers and supports unsubscribe", () => {
    const seen: string[] = [];
    const off = onAuthExpired((d) => seen.push(d.reason ?? ""));
    notifyAuthExpired({ reason: "expired" });
    off();
    notifyAuthExpired({ reason: "again" });
    expect(seen).toEqual(["expired"]);
  });

  it("round-trips a form draft", () => {
    saveFormDraft("pay", { amount: "10", memo: "hi" });
    expect(loadFormDraft("pay")).toEqual({ amount: "10", memo: "hi" });
    clearFormDraft("pay");
    expect(loadFormDraft("pay")).toBeNull();
  });

  it("returns the origin route once, then clears it", () => {
    saveOriginRoute("/pay/abc");
    expect(takeOriginRoute()).toBe("/pay/abc");
    expect(takeOriginRoute()).toBeNull();
  });
});

describe("fetchWithAuth (FE-70)", () => {
  it("fires an auth-expiry event on a 401 response", async () => {
    const listener = vi.fn();
    onAuthExpired(listener);
    global.fetch = vi
      .fn()
      .mockResolvedValue({ status: 401, ok: false }) as unknown as typeof fetch;

    const res = await fetchWithAuth("/api/whoami");
    expect(res.status).toBe(401);
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("does not fire on a successful response", async () => {
    const listener = vi.fn();
    onAuthExpired(listener);
    global.fetch = vi
      .fn()
      .mockResolvedValue({ status: 200, ok: true }) as unknown as typeof fetch;

    await fetchWithAuth("/api/whoami");
    expect(listener).not.toHaveBeenCalled();
  });
});

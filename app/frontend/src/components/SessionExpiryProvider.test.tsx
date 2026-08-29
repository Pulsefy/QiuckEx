// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { SessionExpiryProvider } from "./SessionExpiryProvider";
import { useFormDraft } from "@/hooks/useFormDraft";
import {
  loadFormDraft,
  notifyAuthExpired,
  resetAuthListeners,
} from "@/lib/auth-session";

const pushMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
  usePathname: () => "/pay/link-123",
}));

// A minimal payment-like form that drafts its input.
function PayForm() {
  const [value, setValue] = useFormDraft<{ amount: string }>("pay-form", {
    amount: "",
  });
  return (
    <input
      aria-label="amount"
      value={value.amount}
      onChange={(e) => setValue({ amount: e.target.value })}
    />
  );
}

beforeEach(() => {
  resetAuthListeners();
  window.sessionStorage.clear();
  pushMock.mockClear();
});

afterEach(() => cleanup());

describe("SessionExpiryProvider (FE-70)", () => {
  it("shows a re-auth prompt on auth expiry and preserves form input", async () => {
    render(
      <SessionExpiryProvider onReauthenticate={() => Promise.resolve(true)}>
        <PayForm />
      </SessionExpiryProvider>,
    );

    // User types into the payment form.
    fireEvent.change(screen.getByLabelText("amount"), {
      target: { value: "42.5" },
    });
    // The draft is persisted immediately.
    expect(loadFormDraft("pay-form")).toEqual({ amount: "42.5" });

    // Session expires mid-form.
    notifyAuthExpired({ reason: "Session expired" });
    await waitFor(() =>
      expect(screen.getByRole("dialog", { name: /session expired/i })).toBeTruthy(),
    );

    // The in-progress input is still saved (not lost).
    expect(loadFormDraft("pay-form")).toEqual({ amount: "42.5" });
  });

  it("returns to the originating route after reconnecting", async () => {
    render(
      <SessionExpiryProvider onReauthenticate={() => Promise.resolve(true)}>
        <PayForm />
      </SessionExpiryProvider>,
    );

    notifyAuthExpired();
    await waitFor(() => expect(screen.getByRole("dialog")).toBeTruthy());

    fireEvent.click(screen.getByRole("button", { name: /reconnect/i }));

    // Prompt dismissed and the user is routed back to where they were.
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(pushMock).toHaveBeenCalledWith("/pay/link-123");
  });

  it("keeps the prompt and shows an error when re-auth fails", async () => {
    render(
      <SessionExpiryProvider onReauthenticate={() => Promise.resolve(false)}>
        <PayForm />
      </SessionExpiryProvider>,
    );

    notifyAuthExpired();
    await waitFor(() => expect(screen.getByRole("dialog")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: /reconnect/i }));

    await waitFor(() =>
      expect(screen.getByText(/re-authentication failed/i)).toBeTruthy(),
    );
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(pushMock).not.toHaveBeenCalled();
  });
});

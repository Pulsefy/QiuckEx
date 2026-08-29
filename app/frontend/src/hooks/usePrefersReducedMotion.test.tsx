// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { cleanup, render, screen } from "@testing-library/react";
import { usePrefersReducedMotion } from "./usePrefersReducedMotion";

type Listener = (event: MediaQueryListEvent) => void;

function mockMatchMedia(matches: boolean) {
  let listener: Listener | null = null;
  const mql = {
    matches,
    media: "(prefers-reduced-motion: reduce)",
    addEventListener: (_: string, cb: Listener) => {
      listener = cb;
    },
    removeEventListener: () => {
      listener = null;
    },
    addListener: (cb: Listener) => {
      listener = cb;
    },
    removeListener: () => {
      listener = null;
    },
    dispatch: (next: boolean) =>
      listener?.({ matches: next } as MediaQueryListEvent),
  };
  window.matchMedia = vi.fn().mockReturnValue(mql) as unknown as typeof window.matchMedia;
  return mql;
}

function Probe() {
  const reduced = usePrefersReducedMotion();
  return <span data-testid="v">{reduced ? "reduced" : "full"}</span>;
}

afterEach(() => cleanup());

describe("usePrefersReducedMotion (FE-69)", () => {
  it("returns true when the OS prefers reduced motion", () => {
    mockMatchMedia(true);
    render(<Probe />);
    expect(screen.getByTestId("v").textContent).toBe("reduced");
  });

  it("returns false when reduced motion is not requested", () => {
    mockMatchMedia(false);
    render(<Probe />);
    expect(screen.getByTestId("v").textContent).toBe("full");
  });

  it("global stylesheet neutralizes motion under the reduce media query", () => {
    // Documented check: the shared reset exists so animated surfaces are
    // covered globally rather than per page.
    const css = readFileSync(
      path.resolve(__dirname, "../app/globals.css"),
      "utf8",
    );
    expect(css).toMatch(/prefers-reduced-motion:\s*reduce/);
    expect(css).toMatch(/animation-duration:\s*0\.01ms\s*!important/);
    expect(css).toMatch(/transition-duration:\s*0\.01ms\s*!important/);
  });
});

"use client";

import { useEffect, useState } from "react";

const QUERY = "(prefers-reduced-motion: reduce)";

/**
 * Reports whether the user has requested reduced motion at the OS level
 * (FE-69). Components that drive animation from JavaScript (e.g. auto-playing
 * carousels or spinners) should gate that motion on this hook, in addition to
 * the global CSS reset in `globals.css`.
 *
 * SSR-safe: returns `false` until mounted, then subscribes to changes.
 */
export function usePrefersReducedMotion(): boolean {
  const [prefersReduced, setPrefersReduced] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) {
      return;
    }
    const mql = window.matchMedia(QUERY);
    setPrefersReduced(mql.matches);

    const onChange = (event: MediaQueryListEvent) => {
      setPrefersReduced(event.matches);
    };

    // addEventListener is the modern API; fall back for older engines.
    if (typeof mql.addEventListener === "function") {
      mql.addEventListener("change", onChange);
      return () => mql.removeEventListener("change", onChange);
    }
    mql.addListener(onChange);
    return () => mql.removeListener(onChange);
  }, []);

  return prefersReduced;
}

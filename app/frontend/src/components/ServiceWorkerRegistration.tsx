"use client";

import { useEffect } from "react";
import { registerServiceWorker } from "@/lib/register-sw";

/**
 * Registers the offline/caching service worker after hydration (FE-64).
 * Renders nothing; no-ops outside production and in unsupported browsers.
 */
export function ServiceWorkerRegistration() {
  useEffect(() => {
    registerServiceWorker();
  }, []);
  return null;
}

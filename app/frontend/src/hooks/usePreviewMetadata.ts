"use client";

/**
 * usePreviewMetadata
 *
 * Resolves preview / testnet environment context for the contributor banner.
 *
 * Resolution order (first truthy value wins):
 *  1. NEXT_PUBLIC_VERCEL_ENV          – set automatically by Vercel
 *  2. NEXT_PUBLIC_PREVIEW_ENV_NAME    – manual override (e.g. "staging")
 *  3. NODE_ENV                        – fallback ("development" / "production")
 *
 * Branch is resolved from NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF (Vercel) or
 * NEXT_PUBLIC_BRANCH (manual override).
 *
 * A backend `/preview-metadata` endpoint is fetched when
 * NEXT_PUBLIC_QUICKEX_API_URL is set and the environment is non-production,
 * so that server-side metadata can enrich the banner. The backend response
 * is merged in but the component gracefully degrades if the endpoint is
 * unavailable.
 */

import { useEffect, useState } from "react";
import { getQuickexApiBase } from "@/lib/api";

export interface PreviewMetadata {
  /** Human-readable environment label, e.g. "preview", "staging", "development". */
  envName: string;
  /** Git branch name, e.g. "feat/FE-38-preview-banner". */
  branch: string;
  /** Commit SHA short hash (7 chars), if available. */
  commitSha?: string;
  /** True when the environment is not production. */
  isPreview: boolean;
}

interface UsePreviewMetadataResult {
  metadata: PreviewMetadata | null;
  loading: boolean;
  error: string | null;
}

/**
 * Shape of the optional backend /preview-metadata response payload.
 * The backend may return additional fields; we only consume the ones we need.
 */
interface BackendPreviewMetadata {
  envName?: string;
  branch?: string;
  commitSha?: string;
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/**
 * Derive the environment name from Next.js / Vercel env vars.
 * Never returns "production" so callers can safely trust this value.
 */
function resolveEnvName(): string {
  // Vercel sets this to "production" | "preview" | "development"
  const vercelEnv = process.env.NEXT_PUBLIC_VERCEL_ENV;
  if (vercelEnv && vercelEnv !== "production") return vercelEnv;

  const manualEnv = process.env.NEXT_PUBLIC_PREVIEW_ENV_NAME;
  if (manualEnv) return manualEnv;

  // NODE_ENV is always available but is a build-time constant in Next.js
  return process.env.NODE_ENV === "production" ? "" : process.env.NODE_ENV ?? "development";
}

/**
 * Returns true when the current environment is NOT production.
 */
export function isPreviewEnvironment(): boolean {
  if (process.env.NODE_ENV === "production") {
    // Still allow the banner in Vercel preview deployments even when Next.js
    // reports NODE_ENV=production (Vercel sets its own NEXT_PUBLIC_VERCEL_ENV).
    const vercelEnv = process.env.NEXT_PUBLIC_VERCEL_ENV;
    return vercelEnv === "preview" || vercelEnv === "development";
  }
  return true;
}

function resolveStaticBranch(): string {
  return (
    process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF ||
    process.env.NEXT_PUBLIC_BRANCH ||
    "unknown-branch"
  );
}

function resolveStaticCommit(): string | undefined {
  const sha = process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA;
  return sha ? sha.slice(0, 7) : undefined;
}

// ─── hook ────────────────────────────────────────────────────────────────────

export function usePreviewMetadata(): UsePreviewMetadataResult {
  const [metadata, setMetadata] = useState<PreviewMetadata | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Never render anything in production (belt-and-suspenders check on the
    // client side; the component itself also checks this).
    if (!isPreviewEnvironment()) {
      setLoading(false);
      return;
    }

    let cancelled = false;

    async function load() {
      const staticMeta: PreviewMetadata = {
        envName: resolveEnvName(),
        branch: resolveStaticBranch(),
        commitSha: resolveStaticCommit(),
        isPreview: true,
      };

      // Optimistically show static data while we fetch from the backend.
      if (!cancelled) setMetadata(staticMeta);

      // Attempt to enrich from backend; failures are non-fatal.
      try {
        const apiBase = getQuickexApiBase();
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);

        const res = await fetch(`${apiBase}/preview-metadata`, {
          signal: controller.signal,
          headers: { Accept: "application/json" },
          // No credentials needed — this is a public metadata endpoint.
        });

        clearTimeout(timeout);

        if (res.ok) {
          const remote: BackendPreviewMetadata = await res.json();
          if (!cancelled) {
            setMetadata((prev) =>
              prev
                ? {
                    ...prev,
                    envName: remote.envName ?? prev.envName,
                    branch: remote.branch ?? prev.branch,
                    commitSha: remote.commitSha ?? prev.commitSha,
                  }
                : prev
            );
          }
        }
      } catch {
        // Network / timeout errors are silently swallowed; the banner will
        // display the static metadata resolved from env vars instead.
      }

      if (!cancelled) setLoading(false);
    }

    load();

    return () => {
      cancelled = true;
    };
  }, []);

  return { metadata, loading, error };
}

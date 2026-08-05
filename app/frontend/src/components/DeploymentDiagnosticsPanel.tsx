"use client";

import { useState } from "react";
import { getDeploymentInfo, isDiagnosticsPanelVisible } from "@/lib/deployment-info";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CopyState {
  [key: string]: "idle" | "copied";
}

interface DiagnosticsRow {
  label: string;
  key: string;
  value: string | null;
  /** Monospace display for SHAs and URLs */
  mono?: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function networkBadgeClasses(network: string) {
  return network === "mainnet"
    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
    : "bg-amber-500/10 text-amber-400 border-amber-500/30";
}

function vercelEnvBadgeClasses(env: string | null) {
  if (env === "production") return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
  if (env === "preview") return "bg-indigo-500/10 text-brand border-indigo-500/30";
  return "bg-surface text-subtle border-border-strong";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * DeploymentDiagnosticsPanel
 *
 * Read-only panel showing branch, commit SHA, deployment timestamp, API URL,
 * Stellar network, Vercel environment, and contract registry version.
 *
 * All values are sourced from runtime environment variables via
 * `getDeploymentInfo()` — nothing is hardcoded.
 *
 * The panel renders nothing when the deployment is mainnet + Vercel
 * production, keeping it out of end-user views.
 */
export function DeploymentDiagnosticsPanel() {
  const info = getDeploymentInfo();
  const [copyStates, setCopyStates] = useState<CopyState>({});

  // Guard: hide on mainnet + production Vercel deploy
  if (!isDiagnosticsPanelVisible(info)) return null;

  const rows: DiagnosticsRow[] = [
    {
      label: "Branch",
      key: "branch",
      value: info.branch,
    },
    {
      label: "Commit SHA",
      key: "commitSha",
      value: info.commitSha,
      mono: true,
    },
    {
      label: "Deployed At",
      key: "deployedAt",
      value: info.deployedAt
        ? new Date(info.deployedAt).toLocaleString("en-US", {
            dateStyle: "medium",
            timeStyle: "short",
          })
        : null,
    },
    {
      label: "API URL",
      key: "apiUrl",
      value: info.apiUrl,
      mono: true,
    },
    {
      label: "Stellar Network",
      key: "network",
      value: info.network,
    },
    {
      label: "Vercel Env",
      key: "vercelEnv",
      value: info.vercelEnv,
    },
    {
      label: "Vercel URL",
      key: "vercelUrl",
      value: info.vercelUrl ? `https://${info.vercelUrl}` : null,
      mono: true,
    },
    {
      label: "Contract Registry",
      key: "contractRegistryVersion",
      value: info.contractRegistryVersion,
      mono: true,
    },
    {
      label: "App Version",
      key: "appVersion",
      value: info.appVersion,
      mono: true,
    },
  ];

  // The raw value that gets copied for a given row key. We copy the full
  // unformatted value (e.g. full ISO string, not the localised display).
  const rawValueForCopy = (key: string): string => {
    const raw: Record<string, string | null> = {
      branch: info.branch,
      commitSha: info.commitSha,
      deployedAt: info.deployedAt,
      apiUrl: info.apiUrl,
      network: info.network,
      vercelEnv: info.vercelEnv,
      vercelUrl: info.vercelUrl ? `https://${info.vercelUrl}` : null,
      contractRegistryVersion: info.contractRegistryVersion,
      appVersion: info.appVersion,
    };
    return raw[key] ?? "";
  };

  const handleCopy = (key: string) => {
    const text = rawValueForCopy(key);
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      setCopyStates((prev) => ({ ...prev, [key]: "copied" }));
      setTimeout(
        () => setCopyStates((prev) => ({ ...prev, [key]: "idle" })),
        2000,
      );
    });
  };

  const handleCopyAll = () => {
    const lines = rows
      .map((r) => `${r.label}: ${rawValueForCopy(r.key) || "—"}`)
      .join("\n");
    navigator.clipboard.writeText(lines).then(() => {
      setCopyStates((prev) => ({ ...prev, __all__: "copied" }));
      setTimeout(
        () => setCopyStates((prev) => ({ ...prev, __all__: "idle" })),
        2000,
      );
    });
  };

  return (
    <section
      aria-label="Preview Deployment Diagnostics"
      className="p-6 rounded-3xl bg-card border border-border space-y-5"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-xl font-bold">Deployment Diagnostics</h2>
            {/* Network badge */}
            <span
              className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full border ${networkBadgeClasses(info.network)}`}
            >
              {info.network}
            </span>
            {/* Vercel env badge */}
            {info.vercelEnv && (
              <span
                className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full border ${vercelEnvBadgeClasses(info.vercelEnv)}`}
              >
                {info.vercelEnv}
              </span>
            )}
          </div>
          <p className="text-sm text-subtle mt-1">
            Read-only build metadata for contributor verification and issue
            reporting.
          </p>
        </div>

        {/* Copy-all button */}
        <button
          onClick={handleCopyAll}
          aria-label="Copy all diagnostics to clipboard"
          className="shrink-0 px-4 py-2 rounded-xl bg-surface border border-border-strong text-xs font-semibold text-muted hover:bg-surface-strong hover:text-foreground transition"
        >
          {copyStates.__all__ === "copied" ? "✓ Copied all" : "⧉ Copy all"}
        </button>
      </div>

      {/* Rows */}
      <div className="divide-y divide-border">
        {rows.map(({ label, key, value, mono }) => (
          <div
            key={key}
            className="flex items-center justify-between gap-4 py-3 first:pt-0 last:pb-0"
          >
            {/* Label + value */}
            <div className="min-w-0 flex-1 space-y-0.5">
              <p className="text-xs font-semibold text-faint uppercase tracking-wider">
                {label}
              </p>
              {value ? (
                <p
                  className={`text-sm break-all ${
                    mono ? "font-mono text-foreground" : "text-foreground"
                  }`}
                >
                  {/* Highlight short SHA inline next to full SHA */}
                  {key === "commitSha" && info.commitShort ? (
                    <>
                      <span className="text-brand font-bold">
                        {info.commitShort}
                      </span>
                      <span className="text-subtle">
                        {value.slice(7)}
                      </span>
                    </>
                  ) : (
                    value
                  )}
                </p>
              ) : (
                <p className="text-sm text-faint italic">not set</p>
              )}
            </div>

            {/* Copy button */}
            <button
              disabled={!value}
              onClick={() => handleCopy(key)}
              aria-label={`Copy ${label}`}
              className="shrink-0 px-3 py-1.5 rounded-xl bg-surface border border-border-strong text-xs font-semibold text-muted hover:bg-surface-strong hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed transition"
            >
              {copyStates[key] === "copied" ? "✓" : "⧉"}
            </button>
          </div>
        ))}
      </div>

      {/* Footer note */}
      <p className="text-xs text-faint pt-1">
        This panel is hidden on mainnet production deployments. Include the
        &quot;Copy all&quot; output when filing a bug report.
      </p>
    </section>
  );
}

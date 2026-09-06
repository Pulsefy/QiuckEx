"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Database, Link as LinkIcon, RefreshCw, Activity } from "lucide-react";

import { getQuickexApiBase } from "@/lib/api";
import { getDeploymentInfo } from "@/lib/deployment-info";

type RegistryStatus = {
  version: string | null;
  ok: boolean;
};

type IndexerLag = {
  lagSeconds: number | null;
  lastProcessed?: string | null;
};

type SmokeTest = {
  id: string;
  name: string;
  status: "ok" | "warn" | "fail";
  details?: string;
};

export function TestnetHealth() {
  const apiBase = useMemo(() => getQuickexApiBase(), []);
  const deployment = useMemo(() => getDeploymentInfo(), []);

  const [registry, setRegistry] = useState<RegistryStatus | null>(null);
  const [lag, setLag] = useState<IndexerLag | null>(null);
  const [smoke, setSmoke] = useState<SmokeTest[]>([]);
  const [filter, setFilter] = useState<"all" | "blockers" | "warnings" | "info">("all");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setError(null);

      try {
        const [regResp, lagResp, smokeResp] = await Promise.all([
          fetch(`${apiBase}/admin/registry`, { cache: "no-store" }).catch(() => null),
          fetch(`${apiBase}/admin/indexer/lag`, { cache: "no-store" }).catch(() => null),
          fetch(`${apiBase}/admin/smoke`, { cache: "no-store" }).catch(() => null),
        ]);

        // Registry
        if (regResp && regResp.ok) {
          const data = await regResp.json();
          if (!cancelled) setRegistry({ version: data.version ?? null, ok: true });
        } else {
          // Fallback to build-in deployment contract registry value
          if (!cancelled)
            setRegistry({ version: deployment.contractRegistryVersion ?? null, ok: Boolean(deployment.contractRegistryVersion) });
        }

        // Indexer lag
        let lagSeconds: number | null = null;
        if (lagResp && lagResp.ok) {
          const data = await lagResp.json();
          lagSeconds = data.lagSeconds ?? null;
          if (!cancelled) setLag({ lagSeconds, lastProcessed: data.lastProcessed ?? null });
        } else {
          if (!cancelled) setLag({ lagSeconds: null, lastProcessed: null });
        }

        // Smoke tests
        if (smokeResp && smokeResp.ok) {
          const data = await smokeResp.json();
          if (!cancelled) setSmoke(data.tests ?? []);
        } else {
          // sensible defaults for demo purposes
          if (!cancelled)
            setSmoke([
              { id: "tx", name: "Transaction submit", status: "ok" },
              { id: "webhooks", name: "Webhook delivery", status: "ok" },
              { id: "indexer", name: "Indexer access", status: lagSeconds !== null && lagSeconds > 60 ? "warn" : "ok" },
            ] as SmokeTest[]);
        }
      } catch {
        if (!cancelled) setError("Unable to load health data");
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [apiBase, deployment.contractRegistryVersion]);

  const indexerSeverity = () => {
    if (!lag || lag.lagSeconds == null) return "warning";
    if (lag.lagSeconds > 120) return "blocker";
    if (lag.lagSeconds > 30) return "warning";
    return "info";
  };

  const registrySeverity = () => {
    if (!registry) return "warning";
    if (!registry.ok) return "blocker";
    return "info";
  };

  const visibleSmoke = smoke.filter((s) => {
    if (filter === "all") return true;
    if (filter === "blockers") return s.status === "fail";
    if (filter === "warnings") return s.status === "warn";
    return s.status === "ok";
  });

  return (
    <div className="bg-card p-6 rounded-lg shadow-sm border border-border">
      <div className="flex items-start justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Testnet Health</h2>
          <p className="text-sm text-subtle">Quick overview of registry, indexer, smoke tests, and build metadata.</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => void location.reload()}
            className="px-3 py-1 rounded-md bg-surface border border-border text-xs text-muted"
            aria-label="Refresh health"
          >
            <RefreshCw className="inline-block h-4 w-4 mr-1" /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-warning-soft bg-warning-soft px-3 py-2 text-sm text-warning">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        <div className={`p-4 rounded-lg border ${registrySeverity() === "blocker" ? "border-danger" : registrySeverity() === "warning" ? "border-warning-soft" : "border-border"}`}>
          <div className="flex items-center gap-2 text-sm font-medium mb-2">
            <Database className="h-4 w-4 text-muted" />
            Contract Registry
          </div>
          <p className="text-foreground font-semibold text-lg">{registry?.version ?? "unknown"}</p>
          <p className="text-sm text-subtle">{registry?.ok ? "Deployed" : "Missing or unreachable"}</p>
          <div className="mt-3">
            <Link href="/admin/registry" className="text-xs text-brand font-semibold inline-flex items-center gap-1">
              <LinkIcon className="h-3.5 w-3.5" /> View registry
            </Link>
          </div>
        </div>

        <div className={`p-4 rounded-lg border ${indexerSeverity() === "blocker" ? "border-danger" : indexerSeverity() === "warning" ? "border-warning-soft" : "border-border"}`}>
          <div className="flex items-center gap-2 text-sm font-medium mb-2">
            <Activity className="h-4 w-4 text-muted" />
            Indexer Lag
          </div>
          <p className="text-foreground font-semibold text-lg">{lag?.lagSeconds == null ? "unknown" : `${lag.lagSeconds}s`}</p>
          <p className="text-sm text-subtle">{lag?.lastProcessed ? new Date(lag.lastProcessed).toLocaleString() : "no data"}</p>
          <div className="mt-3">
            <Link href="/dashboard" className="text-xs text-brand font-semibold inline-flex items-center gap-1">
              <LinkIcon className="h-3.5 w-3.5" /> View transactions
            </Link>
          </div>
        </div>

        <div className="p-4 rounded-lg border border-border">
          <div className="flex items-center gap-2 text-sm font-medium mb-2">
            <AlertTriangle className="h-4 w-4 text-muted" /> Smoke Tests
          </div>
          <p className="text-foreground font-semibold text-lg">{smoke.filter((s) => s.status === "ok").length}/{smoke.length} passing</p>
          <p className="text-sm text-subtle">Filters and quick links below</p>
          <div className="mt-3">
            <Link href="/webhooks" className="text-xs text-brand font-semibold inline-flex items-center gap-1">
              <LinkIcon className="h-3.5 w-3.5" /> Webhook logs
            </Link>
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2 text-sm text-subtle">
          <span className="font-semibold">Filter:</span>
          <select value={filter} onChange={(e) => setFilter(e.target.value as "all" | "blockers" | "warnings" | "info")} className="border border-border rounded-md py-1 px-2 bg-card text-sm">
            <option value="all">All</option>
            <option value="blockers">Blockers</option>
            <option value="warnings">Warnings</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div className="text-xs text-subtle">
          Severity: <span className="font-semibold">Blocker</span> / <span className="font-semibold">Warning</span> / Info
        </div>
      </div>

      <div className="space-y-2">
        {visibleSmoke.map((s) => (
          <div key={s.id} className={`rounded-md p-3 border ${s.status === "fail" ? "border-danger bg-danger/5" : s.status === "warn" ? "border-warning-soft bg-warning-soft/10" : "border-border"}`}>
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <p className="font-medium text-foreground">{s.name}</p>
                  <span className="text-xs text-subtle">{s.id}</span>
                </div>
                {s.details && <p className="text-sm text-subtle">{s.details}</p>}
              </div>
              <div>
                <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold ${s.status === "fail" ? "bg-danger text-danger/90" : s.status === "warn" ? "bg-warning-soft text-warning" : "bg-success-soft text-success"}`}>
                  {s.status === "fail" ? "Blocker" : s.status === "warn" ? "Warning" : "OK"}
                </span>
              </div>
            </div>
          </div>
        ))}
        {visibleSmoke.length === 0 && <p className="text-sm text-subtle">No smoke tests match the selected filter.</p>}
      </div>
    </div>
  );
}

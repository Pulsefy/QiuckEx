"use client";

import { useEffect, useMemo, useState } from "react";
import { Activity, DatabaseZap, ShieldAlert } from "lucide-react";

import { getQuickexApiBase } from "@/lib/api";

type HealthResponse = {
  status: string;
  uptime: number;
};

type FlagHealthResponse = {
  flags: unknown[];
  source: string;
  storeAvailable: boolean;
};

export function SystemHealth() {
  const apiBase = useMemo(() => getQuickexApiBase(), []);
  const [apiStatus, setApiStatus] = useState("Checking");
  const [uptime, setUptime] = useState("--");
  const [flagStore, setFlagStore] = useState("Checking");

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const [healthResponse, flagsResponse] = await Promise.all([
          fetch(`${apiBase}/health`, { cache: "no-store" }),
          fetch(`${apiBase}/admin/feature-flags`, { cache: "no-store" }),
        ]);

        if (!healthResponse.ok) {
          throw new Error("Health endpoint unavailable");
        }

        const health = (await healthResponse.json()) as HealthResponse;
        const flags = flagsResponse.ok
          ? ((await flagsResponse.json()) as FlagHealthResponse)
          : null;

        if (!cancelled) {
          setApiStatus(health.status === "ok" ? "Operational" : health.status);
          setUptime(`${Math.floor((health.uptime ?? 0) / 60)}m`);
          setFlagStore(flags?.storeAvailable ? "Persistent" : flags?.source === "bootstrap" ? "Bootstrap" : "Unavailable");
        }
      } catch {
        if (!cancelled) {
          setApiStatus("Unavailable");
          setFlagStore("Unavailable");
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [apiBase]);

  return (
    <div className="bg-card p-6 rounded-lg shadow-sm border border-border">
      <h2 className="text-lg font-semibold text-foreground mb-4">System Health</h2>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 bg-success-soft rounded-lg border border-success-soft">
          <div className="flex items-center space-x-2 text-success mb-2">
            <Activity className="h-5 w-5" />
            <span className="font-medium">API Status</span>
          </div>
          <p className="text-2xl font-bold text-foreground">{apiStatus}</p>
        </div>

        <div className="p-4 bg-brand-soft rounded-lg border border-brand-soft">
          <div className="flex items-center space-x-2 text-brand mb-2">
            <DatabaseZap className="h-5 w-5" />
            <span className="font-medium">Flag Store</span>
          </div>
          <p className="text-2xl font-bold text-foreground">{flagStore}</p>
        </div>

        <div className="p-4 bg-warning-soft rounded-lg border border-warning-soft">
          <div className="flex items-center space-x-2 text-warning mb-2">
            <ShieldAlert className="h-5 w-5" />
            <span className="font-medium">Uptime</span>
          </div>
          <p className="text-2xl font-bold text-foreground">{uptime}</p>
        </div>
      </div>
    </div>
  );
}

"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Search, ShieldCheck } from "lucide-react";

import { getQuickexApiBase } from "@/lib/api";

type Flag = {
  key: string;
  name: string;
  description: string;
  enabled: boolean;
  killSwitch: boolean;
  rolloutPercentage: number;
  environments: string[];
  updatedAt: string;
  updatedBy: string;
};

type FlagsResponse = {
  flags: Flag[];
  source: string;
  storeAvailable: boolean;
};

export function FeatureFlags() {
  const apiBase = useMemo(() => getQuickexApiBase(), []);
  const [flags, setFlags] = useState<Flag[]>([]);
  const [search, setSearch] = useState("");
  const [source, setSource] = useState("cache");
  const [storeAvailable, setStoreAvailable] = useState(true);
  const [savingKey, setSavingKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        setError(null);
        const response = await fetch(`${apiBase}/admin/feature-flags`, {
          cache: "no-store",
        });
        if (!response.ok) {
          throw new Error(`Flag fetch failed (${response.status})`);
        }
        const payload = (await response.json()) as FlagsResponse;
        if (!cancelled) {
          setFlags(payload.flags ?? []);
          setSource(payload.source ?? "cache");
          setStoreAvailable(payload.storeAvailable ?? true);
        }
      } catch (fetchError) {
        if (!cancelled) {
          setError(fetchError instanceof Error ? fetchError.message : "Unable to load flags.");
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [apiBase]);

  const filteredFlags = flags.filter((flag) =>
    `${flag.name} ${flag.description} ${flag.key}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );

  const toggleFlag = async (flag: Flag, field: "enabled" | "killSwitch") => {
    const optimistic = flags.map((entry) =>
      entry.key === flag.key ? { ...entry, [field]: !entry[field] } : entry,
    );
    setFlags(optimistic);
    setSavingKey(`${flag.key}:${field}`);

    try {
      const response = await fetch(`${apiBase}/admin/feature-flags/${flag.key}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "x-admin-actor": "admin-dashboard",
        },
        body: JSON.stringify({ [field]: !flag[field] }),
      });

      if (!response.ok) {
        throw new Error(`Flag update failed (${response.status})`);
      }

      const updated = (await response.json()) as Flag;
      setFlags((current) =>
        current.map((entry) => (entry.key === updated.key ? updated : entry)),
      );
      setStoreAvailable(true);
      setError(null);
    } catch (updateError) {
      setFlags(flags);
      setError(
        updateError instanceof Error
          ? updateError.message
          : "Unable to update feature flag.",
      );
    } finally {
      setSavingKey(null);
    }
  };

  return (
    <div className="bg-card p-6 rounded-lg shadow-sm border border-border">
      <div className="flex flex-col gap-4 mb-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-foreground">Safety Controls</h2>
            <p className="text-sm text-subtle">
              Source: <span className="font-medium text-muted">{source}</span>
            </p>
          </div>
          <div
            className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold ${
              storeAvailable
                ? "bg-success-soft text-success"
                : "bg-warning-soft text-warning"
            }`}
          >
            {storeAvailable ? <ShieldCheck className="h-3.5 w-3.5" /> : <AlertTriangle className="h-3.5 w-3.5" />}
            {storeAvailable ? "Persistent store healthy" : "Bootstrap fallback active"}
          </div>
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-subtle" />
          <input
            type="text"
            placeholder="Search flags..."
            className="pl-9 pr-4 py-2 text-sm border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-brand w-full"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
      </div>

      {error && (
        <p className="mb-4 rounded-md border border-warning-soft bg-warning-soft px-3 py-2 text-sm text-warning">
          {error}
        </p>
      )}

      <div className="space-y-4">
        {filteredFlags.map((flag) => (
          <div
            key={flag.key}
            className="rounded-lg border border-border px-4 py-4"
          >
            <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="font-medium text-foreground">{flag.name}</p>
                  <span className="rounded-full bg-surface px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-muted">
                    {flag.key}
                  </span>
                </div>
                <p className="text-sm text-subtle">{flag.description}</p>
                <p className="text-xs text-subtle">
                  Rollout {flag.rolloutPercentage}% • Environments {flag.environments.join(", ") || "all"} • Updated by {flag.updatedBy}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3 sm:w-auto">
                <label className="flex items-center gap-3 rounded-lg border border-border px-3 py-2">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-subtle">Enabled</p>
                    <p className="text-sm text-muted">{flag.enabled ? "On" : "Off"}</p>
                  </div>
                  <input
                    type="checkbox"
                    className="h-4 w-4"
                    checked={flag.enabled}
                    disabled={savingKey === `${flag.key}:enabled`}
                    onChange={() => void toggleFlag(flag, "enabled")}
                  />
                </label>

                <label className="flex items-center gap-3 rounded-lg border border-border px-3 py-2">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wide text-subtle">Kill Switch</p>
                    <p className="text-sm text-muted">{flag.killSwitch ? "Armed" : "Standby"}</p>
                  </div>
                  <input
                    type="checkbox"
                    className="h-4 w-4"
                    checked={flag.killSwitch}
                    disabled={savingKey === `${flag.key}:killSwitch`}
                    onChange={() => void toggleFlag(flag, "killSwitch")}
                  />
                </label>
              </div>
            </div>
          </div>
        ))}
        {filteredFlags.length === 0 && (
          <p className="text-sm text-subtle text-center py-4">No flags found.</p>
        )}
      </div>
    </div>
  );
}

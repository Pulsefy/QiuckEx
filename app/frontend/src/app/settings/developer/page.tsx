"use client";

import CreateAPIKeyModal from "@/components/CreateAPIKeyModal";
import { getQuickexApiBase } from "@/lib/api";
import {
  type ApiKey,
  type NewKeyForm,
} from "@/app/settings/developer/api-key-types";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

type UsageSummary = {
  total_keys: number;
  total_requests: number;
  quota: number;
};

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${getQuickexApiBase()}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.message ?? `Request failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Page component
// ---------------------------------------------------------------------------

export default function DeveloperSettings() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [usage, setUsage] = useState<UsageSummary>({ total_keys: 0, total_requests: 0, quota: 0 });
  const [loadingKeys, setLoadingKeys] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [rotatingId, setRotatingId] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<NewKeyForm>({ name: "", scopes: [] });
  const [error, setError] = useState<string | null>(null);

  // ---------------------------------------------------------------------------
  // Data fetching
  // ---------------------------------------------------------------------------

  const loadKeys = useCallback(async () => {
    try {
      const [fetchedKeys, fetchedUsage] = await Promise.all([
        apiFetch<ApiKey[]>("/api-keys"),
        apiFetch<UsageSummary>("/api-keys/usage"),
      ]);
      setKeys(fetchedKeys.map((k) => ({ ...k, revealed: false, copyLabel: "Copy" })));
      setUsage(fetchedUsage);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoadingKeys(false);
    }
  }, []);

  useEffect(() => {
    loadKeys();
  }, [loadKeys]);

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  const toggleReveal = (id: string) => {
    setKeys((prev) =>
      prev.map((k) => (k.id === id ? { ...k, revealed: !k.revealed } : k)),
    );
  };

  const copyKey = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setKeys((prev) =>
      prev.map((k) => (k.id === id ? { ...k, copyLabel: "Copied!" } : k)),
    );
    setTimeout(() => {
      setKeys((prev) =>
        prev.map((k) => (k.id === id ? { ...k, copyLabel: "Copy" } : k)),
      );
    }, 2000);
  };

  const revokeKey = async (id: string) => {
    try {
      await apiFetch(`/api-keys/${id}`, { method: "DELETE" });
      setKeys((prev) => prev.filter((k) => k.id !== id));
      setUsage((u) => ({ ...u, total_keys: u.total_keys - 1 }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRevokeId(null);
    }
  };

  const rotateKey = async (id: string) => {
    setRotatingId(id);
    try {
      const rotated = await apiFetch<ApiKey & { key: string }>(`/api-keys/${id}/rotate`, {
        method: "POST",
      });
      setKeys((prev) =>
        prev.map((k) =>
          k.id === id
            ? {
                ...rotated,
                revealed: true,
                rawKey: rotated.key,
                copyLabel: "Copy",
              }
            : k,
        ),
      );
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setRotatingId(null);
    }
  };

  const generateKey = async () => {
    if (!newKey.name.trim() || newKey.scopes.length === 0) return;
    setCreating(true);
    setError(null);
    try {
      const created = await apiFetch<ApiKey & { key: string }>("/api-keys", {
        method: "POST",
        body: JSON.stringify({ name: newKey.name.trim(), scopes: newKey.scopes }),
      });
      setKeys((prev) => [
        { ...created, revealed: true, rawKey: created.key, copyLabel: "Copy" },
        ...prev,
      ]);
      setUsage((u) => ({ ...u, total_keys: u.total_keys + 1 }));
      setNewKey({ name: "", scopes: [] });
      setModalOpen(false);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Derived UI values
  // ---------------------------------------------------------------------------

  const usedRequests = usage.total_requests;
  const quota = usage.quota || 10000;
  const usagePercent = Math.min(100, Math.round((usedRequests / quota) * 100));
  const usageColor =
    usagePercent >= 90
      ? "bg-red-500"
      : usagePercent >= 70
        ? "bg-amber-500"
        : "bg-indigo-500";

  const resetDate = new Date();
  resetDate.setMonth(resetDate.getMonth() + 1, 1);
  const resetLabel = resetDate.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="relative min-h-screen text-white selection:bg-indigo-500/30 overflow-x-hidden">
      {/* Background glows */}
      <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px] pointer-events-none" />
      <div className="fixed bottom-[-20%] right-[-30%] w-[50%] h-[50%] bg-purple-500/5 blur-[100px] pointer-events-none" />

      <div className="max-w-5xl mx-auto pt-8">
        {/* Page heading */}
        <h1 className="text-4xl font-black mb-6">Settings</h1>

        {/* Tab nav */}
        <nav className="flex gap-3 mb-10">
          <Link
            href="/settings"
            className="px-4 py-2 rounded-xl border border-white/10 text-sm font-semibold text-neutral-400 hover:text-white hover:bg-white/5 transition"
          >
            General
          </Link>
          <Link
            href="/settings/developer"
            className="px-4 py-2 rounded-xl border border-indigo-500/40 bg-indigo-500/10 text-indigo-300 text-sm font-semibold"
          >
            Developer
          </Link>
        </nav>

        {/* Error banner */}
        {error && (
          <div className="mb-6 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="ml-4 text-red-300 hover:text-white text-xs font-bold">
              Dismiss
            </button>
          </div>
        )}

        <div className="space-y-6">
          {/* API Keys section */}
          <section className="p-6 rounded-3xl bg-neutral-900/40 border border-white/5 space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold">API Keys</h2>
                <p className="text-sm text-neutral-500 mt-1">
                  Manage keys used to authenticate requests to the QuickEx API.
                </p>
              </div>
              <button
                onClick={() => setModalOpen(true)}
                className="px-4 py-2.5 rounded-xl bg-indigo-500 hover:bg-indigo-400 active:scale-95 text-white text-sm font-bold transition"
              >
                + Create New Key
              </button>
            </div>

            {/* Key list */}
            <div className="space-y-3">
              {loadingKeys && (
                <div className="text-center py-10 text-neutral-600 text-sm">
                  Loading keys…
                </div>
              )}

              {!loadingKeys && keys.length === 0 && (
                <div className="text-center py-10 text-neutral-600 text-sm">
                  No API keys yet. Create one to get started.
                </div>
              )}

              {keys.map((key) => {
                const displayKey = key.rawKey
                  ? key.rawKey
                  : key.revealed
                    ? key.key_prefix + "•".repeat(20)
                    : "qx_live_" + "•".repeat(20);

                return (
                  <div
                    key={key.id}
                    className="flex flex-col sm:flex-row sm:items-start gap-4 p-4 rounded-2xl bg-black/30 border border-white/5"
                  >
                    {/* Key info */}
                    <div className="flex-1 min-w-0 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-sm">{key.name}</span>
                        {key.scopes.map((scope) => (
                          <span
                            key={scope}
                            className="text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full border text-indigo-300 border-indigo-500/30 bg-indigo-500/10"
                          >
                            {scope}
                          </span>
                        ))}
                      </div>
                      <div className="font-mono text-sm text-neutral-400 truncate">
                        {displayKey}
                      </div>
                      {key.rawKey && (
                        <p className="text-xs text-amber-400">
                          Save this key now — it won&apos;t be shown again.
                        </p>
                      )}
                      <div className="text-xs text-neutral-600">
                        Created{" "}
                        {new Date(key.created_at).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })}
                        {key.last_used_at && (
                          <span>
                            {" · "}Last used{" "}
                            {new Date(key.last_used_at).toLocaleDateString("en-US", {
                              month: "short",
                              day: "numeric",
                              year: "numeric",
                            })}
                          </span>
                        )}
                        <span className="ml-2 text-neutral-700">
                          {key.request_count.toLocaleString()} requests
                        </span>
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 shrink-0 flex-wrap">
                      {!key.rawKey && (
                        <button
                          onClick={() => toggleReveal(key.id)}
                          className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-semibold text-neutral-300 hover:bg-white/10 hover:text-white transition"
                        >
                          {key.revealed ? "Hide" : "Reveal"}
                        </button>
                      )}

                      <button
                        onClick={() => copyKey(key.id, key.rawKey ?? key.key_prefix)}
                        className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-semibold text-neutral-300 hover:bg-white/10 hover:text-white transition"
                      >
                        {key.copyLabel === "Copied!" ? "✓ Copied!" : "⧉ Copy"}
                      </button>

                      <button
                        onClick={() => rotateKey(key.id)}
                        disabled={rotatingId === key.id}
                        className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-semibold text-neutral-300 hover:bg-white/10 hover:text-white disabled:opacity-40 transition"
                      >
                        {rotatingId === key.id ? "Rotating…" : "↻ Rotate"}
                      </button>

                      {revokeId === key.id ? (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => revokeKey(key.id)}
                            className="px-3 py-2 rounded-xl bg-red-500/20 border border-red-500/30 text-xs font-bold text-red-400 hover:bg-red-500/30 transition"
                          >
                            Confirm
                          </button>
                          <button
                            onClick={() => setRevokeId(null)}
                            className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-semibold text-neutral-400 hover:text-white transition"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setRevokeId(key.id)}
                          className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-semibold text-red-400 hover:bg-red-500/10 hover:border-red-500/20 transition"
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Usage quota section */}
          <section className="p-6 rounded-3xl bg-neutral-900/40 border border-white/5 space-y-4">
            <div>
              <h2 className="text-xl font-bold">Monthly Usage</h2>
              <p className="text-sm text-neutral-500 mt-1">
                API requests used this billing period across all keys.
              </p>
            </div>

            <div className="space-y-3">
              <div className="flex justify-between items-end">
                <span className="text-3xl font-black">
                  {usedRequests.toLocaleString()}
                  <span className="text-lg text-neutral-500 font-semibold ml-1">
                    / {quota.toLocaleString()}
                  </span>
                </span>
                <span className="text-sm font-bold text-neutral-400">
                  {usagePercent}% used
                </span>
              </div>

              {/* Progress bar */}
              <div className="h-2.5 w-full rounded-full bg-white/5 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ${usageColor}`}
                  style={{ width: `${usagePercent}%` }}
                />
              </div>

              <p className="text-xs text-neutral-600">
                {(quota - usedRequests).toLocaleString()} requests remaining.
                Resets on {resetLabel}.
              </p>
            </div>
          </section>

          {/* Scope reference */}
          <section className="p-6 rounded-3xl bg-neutral-900/40 border border-white/5 space-y-4">
            <h2 className="text-xl font-bold">Scope Reference</h2>
            <div className="grid sm:grid-cols-2 gap-4">
              {[
                { scope: "links:read",        desc: "Fetch and query payment links. Cannot create or modify." },
                { scope: "links:write",       desc: "Create and update payment links. Includes links:read." },
                { scope: "transactions:read", desc: "Read transaction history from the Horizon API." },
                { scope: "usernames:read",    desc: "Look up registered QuickEx usernames." },
              ].map(({ scope, desc }) => (
                <div
                  key={scope}
                  className="p-4 rounded-2xl bg-indigo-500/5 border border-indigo-500/20 space-y-1"
                >
                  <span className="text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full text-indigo-300 border border-indigo-500/30 bg-indigo-500/10 font-mono">
                    {scope}
                  </span>
                  <p className="text-sm text-neutral-400 mt-2">{desc}</p>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>

      {/* Create Key Modal */}
      {modalOpen && (
        <CreateAPIKeyModal
          setModalOpen={setModalOpen}
          newKey={newKey}
          setNewKey={setNewKey}
          generateKey={generateKey}
          loading={creating}
        />
      )}
    </div>
  );
}

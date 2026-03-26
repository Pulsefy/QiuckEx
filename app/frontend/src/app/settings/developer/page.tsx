"use client";

import CreateAPIKeyModal from "@/components/CreateAPIKeyModal";
import Link from "next/link";
import { useState } from "react";

export type Scope = "read" | "write";

export type ApiKey = {
  id: string;
  name: string;
  key: string;
  scope: Scope;
  createdAt: string;
  revealed: boolean;
  copyLabel: string;
};

export type NewKeyForm = {
  name: string;
  scope: Scope;
};

const MOCK_KEYS: ApiKey[] = [
  {
    id: "1",
    name: "Production App",
    key: "sk-prod-a1b2c3d4e5f6g7h8i9j0klmnopqrstu",
    scope: "write",
    createdAt: "Jan 12, 2026",
    revealed: false,
    copyLabel: "Copy",
  },
  {
    id: "2",
    name: "Analytics Service",
    key: "sk-read-z9y8x7w6v5u4t3s2r1q0ponmlkjihg",
    scope: "read",
    createdAt: "Feb 3, 2026",
    revealed: false,
    copyLabel: "Copy",
  },
];

const USAGE = {
  used: 7340,
  limit: 10000,
};

export default function DeveloperSettings() {
  const [keys, setKeys] = useState<ApiKey[]>(MOCK_KEYS);
  const [modalOpen, setModalOpen] = useState(false);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<NewKeyForm>({ name: "", scope: "read" });

  const toggleReveal = (id: string) => {
    setKeys((prev) =>
      prev.map((k) => (k.id === id ? { ...k, revealed: !k.revealed } : k)),
    );
  };

  const copyKey = (id: string, key: string) => {
    navigator.clipboard.writeText(key);
    setKeys((prev) =>
      prev.map((k) => (k.id === id ? { ...k, copyLabel: "Copied!" } : k)),
    );
    setTimeout(() => {
      setKeys((prev) =>
        prev.map((k) => (k.id === id ? { ...k, copyLabel: "Copy" } : k)),
      );
    }, 2000);
  };

  const revokeKey = (id: string) => {
    setKeys((prev) => prev.filter((k) => k.id !== id));
    setRevokeId(null);
  };

  const generateKey = () => {
    if (!newKey.name.trim()) return;
    const prefix = newKey.scope === "write" ? "sk-prod" : "sk-read";
    const random = Math.random().toString(36).slice(2, 34).padEnd(32, "0");
    const created: ApiKey = {
      id: Date.now().toString(),
      name: newKey.name.trim(),
      key: `${prefix}-${random}`,
      scope: newKey.scope,
      createdAt: new Date().toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
      }),
      revealed: false,
      copyLabel: "Copy",
    };
    setKeys((prev) => [created, ...prev]);
    setNewKey({ name: "", scope: "read" });
    setModalOpen(false);
  };

  const usagePercent = Math.round((USAGE.used / USAGE.limit) * 100);
  const usageColor =
    usagePercent >= 90
      ? "bg-red-500"
      : usagePercent >= 70
        ? "bg-amber-500"
        : "bg-indigo-500";

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
              {keys.length === 0 && (
                <div className="text-center py-10 text-neutral-600 text-sm">
                  No API keys yet. Create one to get started.
                </div>
              )}

              {keys.map((key) => (
                <div
                  key={key.id}
                  className="flex flex-col sm:flex-row sm:items-center gap-4 p-4 rounded-2xl bg-black/30 border border-white/5"
                >
                  {/* Key info */}
                  <div className="flex-1 min-w-0 space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-sm">{key.name}</span>
                      <span
                        className={`text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full border ${
                          key.scope === "write"
                            ? "text-purple-300 border-purple-500/30 bg-purple-500/10"
                            : "text-indigo-300 border-indigo-500/30 bg-indigo-500/10"
                        }`}
                      >
                        {key.scope}
                      </span>
                    </div>
                    <div className="font-mono text-sm text-neutral-400 truncate">
                      {key.revealed ? key.key : "sk-" + "•".repeat(28)}
                    </div>
                    <div className="text-xs text-neutral-600">
                      Created {key.createdAt}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => toggleReveal(key.id)}
                      className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-semibold text-neutral-300 hover:bg-white/10 hover:text-white transition"
                    >
                      {key.revealed ? "Hide" : "Reveal"}
                    </button>

                    <button
                      onClick={() => copyKey(key.id, key.key)}
                      className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-semibold text-neutral-300 hover:bg-white/10 hover:text-white transition"
                    >
                      {key.copyLabel === "Copied!" ? "✓ Copied!" : "⧉ Copy"}
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
              ))}
            </div>
          </section>

          {/* Usage quota section */}
          <section className="p-6 rounded-3xl bg-neutral-900/40 border border-white/5 space-y-4">
            <div>
              <h2 className="text-xl font-bold">Monthly Usage</h2>
              <p className="text-sm text-neutral-500 mt-1">
                API requests used this billing period.
              </p>
            </div>

            <div className="space-y-3">
              <div className="flex justify-between items-end">
                <span className="text-3xl font-black">
                  {USAGE.used.toLocaleString()}
                  <span className="text-lg text-neutral-500 font-semibold ml-1">
                    / {USAGE.limit.toLocaleString()}
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
                {(USAGE.limit - USAGE.used).toLocaleString()} requests
                remaining. Resets on Apr 1, 2026.
              </p>
            </div>
          </section>

          {/* Scope reference */}
          <section className="p-6 rounded-3xl bg-neutral-900/40 border border-white/5 space-y-4">
            <h2 className="text-xl font-bold">Scope Reference</h2>
            <div className="grid sm:grid-cols-2 gap-4">
              <div className="p-4 rounded-2xl bg-indigo-500/5 border border-indigo-500/20 space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full text-indigo-300 border border-indigo-500/30 bg-indigo-500/10">
                    Read
                  </span>
                </div>
                <p className="text-sm text-neutral-400 mt-2">
                  Can fetch data, retrieve payment links, and query account
                  info. Cannot create or modify any resources.
                </p>
              </div>
              <div className="p-4 rounded-2xl bg-purple-500/5 border border-purple-500/20 space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full text-purple-300 border border-purple-500/30 bg-purple-500/10">
                    Write
                  </span>
                </div>
                <p className="text-sm text-neutral-400 mt-2">
                  Full access — can generate payment links, update settings, and
                  perform all Read actions. Use with care.
                </p>
              </div>
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
        />
      )}
    </div>
  );
}

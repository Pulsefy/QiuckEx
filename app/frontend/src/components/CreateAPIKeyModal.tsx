import {
  AVAILABLE_SCOPES,
  type ApiKeyScope,
  type NewKeyForm,
} from "@/app/settings/developer/api-key-types";
import React from "react";

type Props = {
  setModalOpen: (state: boolean) => void;
  newKey: NewKeyForm;
  setNewKey: React.Dispatch<React.SetStateAction<NewKeyForm>>;
  generateKey: () => void;
  loading: boolean;
};

const SCOPE_LABELS: Record<ApiKeyScope, { label: string; description: string }> = {
  "links:read":       { label: "links:read",       description: "Fetch and query payment links" },
  "links:write":      { label: "links:write",       description: "Create and update payment links" },
  "transactions:read":{ label: "transactions:read", description: "Read transaction history" },
  "usernames:read":   { label: "usernames:read",    description: "Look up registered usernames" },
};

export default function CreateAPIKeyModal({
  setModalOpen,
  newKey,
  setNewKey,
  generateKey,
  loading,
}: Props) {
  const toggleScope = (scope: ApiKeyScope) => {
    setNewKey((prev) => ({
      ...prev,
      scopes: prev.scopes.includes(scope)
        ? prev.scopes.filter((s) => s !== scope)
        : [...prev.scopes, scope],
    }));
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-card backdrop-blur-sm"
        onClick={() => !loading && setModalOpen(false)}
      />

      {/* Modal */}
      <div className="relative w-full max-w-md bg-card border border-border-strong rounded-3xl p-8 shadow-2xl space-y-6">
        <h3 className="text-xl font-black">Create New API Key</h3>

        {/* Key name */}
        <div className="space-y-2">
          <label className="text-xs font-black uppercase tracking-widest text-subtle">
            Key Name
          </label>
          <input
            type="text"
            placeholder="e.g. Production App"
            value={newKey.name}
            onChange={(e) =>
              setNewKey((prev) => ({ ...prev, name: e.target.value }))
            }
            className="w-full bg-surface-strong border border-border-strong rounded-xl px-4 py-3 text-foreground text-sm font-semibold focus:outline-none focus:border-indigo-500/60 placeholder:text-faint"
          />
        </div>

        {/* Scope selection */}
        <div className="space-y-2">
          <label className="text-xs font-black uppercase tracking-widest text-subtle">
            Scopes
          </label>
          <div className="space-y-2">
            {AVAILABLE_SCOPES.map((scope) => {
              const active = newKey.scopes.includes(scope);
              return (
                <button
                  key={scope}
                  onClick={() => toggleScope(scope)}
                  className={`w-full p-3 rounded-xl border text-left transition flex items-center gap-3 ${
                    active
                      ? "border-indigo-500/40 bg-indigo-500/10"
                      : "border-border-strong bg-surface hover:bg-surface-strong"
                  }`}
                >
                  <div
                    className={`w-4 h-4 rounded border flex-shrink-0 flex items-center justify-center text-[10px] ${
                      active
                        ? "border-indigo-500 bg-indigo-500 text-white"
                        : "border-border-strong"
                    }`}
                  >
                    {active && "✓"}
                  </div>
                  <div>
                    <div className={`text-xs font-bold font-mono ${active ? "text-brand" : "text-subtle"}`}>
                      {SCOPE_LABELS[scope].label}
                    </div>
                    <div className="text-xs text-faint mt-0.5">
                      {SCOPE_LABELS[scope].description}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-3 pt-2">
          <button
            onClick={() => setModalOpen(false)}
            disabled={loading}
            className="flex-1 py-3 rounded-xl border border-border-strong text-sm font-semibold text-subtle hover:text-foreground hover:bg-surface disabled:opacity-40 transition"
          >
            Cancel
          </button>
          <button
            onClick={generateKey}
            disabled={!newKey.name.trim() || newKey.scopes.length === 0 || loading}
            className="flex-1 py-3 rounded-xl bg-indigo-500 hover:bg-indigo-400 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-bold transition active:scale-95"
          >
            {loading ? "Creating…" : "Generate Key"}
          </button>
        </div>
      </div>
    </div>
  );
}

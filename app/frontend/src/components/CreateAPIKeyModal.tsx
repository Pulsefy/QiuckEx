import { NewKeyForm, Scope } from "@/app/Settings/developer/page";
import React from "react";

type Props = {
  setModalOpen: (state: boolean) => void;
  newKey: NewKeyForm;
  setNewKey: React.Dispatch<React.SetStateAction<NewKeyForm>>;
  generateKey: () => void;
};

export default function CreateAPIKeyModal({
  setModalOpen,
  newKey,
  setNewKey,
  generateKey,
}: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={() => setModalOpen(false)}
      />

      {/* Modal */}
      <div className="relative w-full max-w-md bg-neutral-900 border border-white/10 rounded-3xl p-8 shadow-2xl space-y-6">
        <h3 className="text-xl font-black">Create New API Key</h3>

        {/* Key name */}
        <div className="space-y-2">
          <label className="text-xs font-black uppercase tracking-widest text-neutral-500">
            Key Name
          </label>
          <input
            type="text"
            placeholder="e.g. Production App"
            value={newKey.name}
            onChange={(e) =>
              setNewKey((prev) => ({ ...prev, name: e.target.value }))
            }
            className="w-full bg-neutral-800 border border-white/10 rounded-xl px-4 py-3 text-white text-sm font-semibold focus:outline-none focus:border-indigo-500/60 placeholder:text-neutral-600"
          />
        </div>

        {/* Scope selection */}
        <div className="space-y-2">
          <label className="text-xs font-black uppercase tracking-widest text-neutral-500">
            Scope
          </label>
          <div className="grid grid-cols-2 gap-3">
            {(["read", "write"] as Scope[]).map((s) => (
              <button
                key={s}
                onClick={() => setNewKey((prev) => ({ ...prev, scope: s }))}
                className={`p-4 rounded-2xl border text-left transition ${
                  newKey.scope === s
                    ? s === "write"
                      ? "border-purple-500/40 bg-purple-500/10"
                      : "border-indigo-500/40 bg-indigo-500/10"
                    : "border-white/10 bg-white/5 hover:bg-white/10"
                }`}
              >
                <div
                  className={`text-xs font-black uppercase tracking-widest mb-1 ${
                    newKey.scope === s
                      ? s === "write"
                        ? "text-purple-300"
                        : "text-indigo-300"
                      : "text-neutral-400"
                  }`}
                >
                  {s}
                </div>
                <div className="text-xs text-neutral-500">
                  {s === "read"
                    ? "Fetch & query only"
                    : "Full read & write access"}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-3 pt-2">
          <button
            onClick={() => setModalOpen(false)}
            className="flex-1 py-3 rounded-xl border border-white/10 text-sm font-semibold text-neutral-400 hover:text-white hover:bg-white/5 transition"
          >
            Cancel
          </button>
          <button
            onClick={generateKey}
            disabled={!newKey.name.trim()}
            className="flex-1 py-3 rounded-xl bg-indigo-500 hover:bg-indigo-400 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-bold transition active:scale-95"
          >
            Generate Key
          </button>
        </div>
      </div>
    </div>
  );
}

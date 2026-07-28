"use client";

import { useState } from "react";

interface Workspace {
  id: string;
  name: string;
  role: "admin" | "operator" | "viewer";
}

const workspaces: Workspace[] = [
  { id: "1", name: "Personal Workspace", role: "admin" },
  { id: "2", name: "Pulsefy Team", role: "operator" },
  { id: "3", name: "Stellar Devs", role: "viewer" },
];

export function WorkspaceSwitcher() {
  const [activeWorkspace, setActiveWorkspace] = useState(workspaces[0]);
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-3 px-3 py-2 bg-surface border border-border-strong rounded-xl hover:bg-surface-strong transition"
      >
        <div className="w-6 h-6 bg-indigo-500 rounded flex items-center justify-center text-[10px] font-bold text-white">
          {activeWorkspace.name[0]}
        </div>
        <div className="text-left hidden sm:block">
          <p className="text-xs font-bold leading-none mb-1">{activeWorkspace.name}</p>
          <p className="text-[10px] text-subtle leading-none capitalize">{activeWorkspace.role}</p>
        </div>
        <span className="text-subtle text-xs">▼</span>
      </button>

      {isOpen && (
        <>
          <div 
            className="fixed inset-0 z-40" 
            onClick={() => setIsOpen(false)}
          />
          <div className="absolute top-full left-0 mt-2 w-56 bg-card border border-border-strong rounded-2xl shadow-2xl z-50 overflow-hidden backdrop-blur-3xl">
            <div className="p-2 space-y-1">
              {workspaces.map((ws) => (
                <button
                  key={ws.id}
                  onClick={() => {
                    setActiveWorkspace(ws);
                    setIsOpen(false);
                  }}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-xl transition text-left ${
                    activeWorkspace.id === ws.id ? "bg-surface-strong" : "hover:bg-surface"
                  }`}
                >
                  <div className="w-8 h-8 bg-surface-strong rounded-lg flex items-center justify-center font-bold">
                    {ws.name[0]}
                  </div>
                  <div>
                    <p className="text-sm font-bold">{ws.name}</p>
                    <p className="text-[10px] text-subtle capitalize">{ws.role}</p>
                  </div>
                </button>
              ))}
            </div>
            <div className="p-2 border-t border-border bg-surface">
              <button className="w-full px-3 py-2 rounded-xl text-xs font-bold text-indigo-400 hover:bg-indigo-500/10 transition text-left">
                + Create Workspace
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

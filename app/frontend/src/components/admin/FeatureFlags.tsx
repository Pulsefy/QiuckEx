"use client";

import { useState } from "react";
import { Search } from "lucide-react";

interface Flag {
  id: string;
  name: string;
  enabled: boolean;
  description: string;
}

const INITIAL_FLAGS: Flag[] = [
  { id: "beta-features", name: "Beta Features", enabled: true, description: "Enable beta features for testing" },
  { id: "new-dashboard", name: "New Dashboard UI", enabled: false, description: "Show the redesigned dashboard" },
  { id: "maintenance-mode", name: "Maintenance Mode", enabled: false, description: "Block all non-admin traffic" },
];

export function FeatureFlags() {
  const [flags, setFlags] = useState<Flag[]>(INITIAL_FLAGS);
  const [search, setSearch] = useState("");

  const filteredFlags = flags.filter(f => 
    f.name.toLowerCase().includes(search.toLowerCase()) || 
    f.description.toLowerCase().includes(search.toLowerCase())
  );

  const toggleFlag = (id: string) => {
    // Flag changes are reflected immediately in UI
    setFlags(flags.map(f => f.id === id ? { ...f, enabled: !f.enabled } : f));
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-semibold text-gray-800">Feature Flags</h2>
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search flags..."
            className="pl-9 pr-4 py-2 text-sm border border-gray-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>
      <div className="space-y-4">
        {filteredFlags.map(flag => (
          <div key={flag.id} className="flex items-center justify-between py-3 border-b border-gray-100 last:border-0">
            <div>
              <p className="font-medium text-gray-800">{flag.name}</p>
              <p className="text-sm text-gray-500">{flag.description}</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" className="sr-only peer" checked={flag.enabled} onChange={() => toggleFlag(flag.id)} />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>
        ))}
        {filteredFlags.length === 0 && (
          <p className="text-sm text-gray-500 text-center py-4">No flags found.</p>
        )}
      </div>
    </div>
  );
}

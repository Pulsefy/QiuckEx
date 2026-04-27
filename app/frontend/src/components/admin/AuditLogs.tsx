"use client";

import { useState } from "react";
import { Filter } from "lucide-react";

interface AuditLog {
  id: string;
  action: string;
  actor: string;
  timestamp: string;
  details: string;
}

const MOCK_LOGS: AuditLog[] = [
  { id: "1", action: "FLAG_TOGGLE", actor: "admin@pulsefy.io", timestamp: "2026-04-27T10:00:00Z", details: "Enabled beta-features" },
  { id: "2", action: "USER_BAN", actor: "admin@pulsefy.io", timestamp: "2026-04-27T09:15:00Z", details: "Banned user ID 4091" },
  { id: "3", action: "SYSTEM_RESTART", actor: "system", timestamp: "2026-04-26T23:00:00Z", details: "Scheduled worker restart" },
];

export function AuditLogs() {
  const [filter, setFilter] = useState("ALL");

  const filteredLogs = MOCK_LOGS.filter(log => filter === "ALL" || log.action === filter);

  const actions = ["ALL", ...Array.from(new Set(MOCK_LOGS.map(l => l.action)))];

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-lg font-semibold text-gray-800">Audit Logs (Read-only)</h2>
        <div className="flex items-center space-x-2">
          <Filter className="h-4 w-4 text-gray-500" />
          <select 
            className="border border-gray-200 rounded-md py-1.5 px-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            {actions.map(a => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm text-gray-500">
          <thead className="text-xs text-gray-700 uppercase bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="px-4 py-3 rounded-tl-lg">Timestamp</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3 rounded-tr-lg">Details</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map(log => (
              <tr key={log.id} className="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                <td className="px-4 py-3 whitespace-nowrap">{new Date(log.timestamp).toLocaleString()}</td>
                <td className="px-4 py-3">
                  <span className="bg-gray-100 text-gray-800 px-2 py-1 rounded text-xs font-medium border border-gray-200">
                    {log.action}
                  </span>
                </td>
                <td className="px-4 py-3">{log.actor}</td>
                <td className="px-4 py-3">{log.details}</td>
              </tr>
            ))}
            {filteredLogs.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-gray-500">
                  No logs found matching the selected filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

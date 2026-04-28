"use client";

import { useEffect, useMemo, useState } from "react";
import { Filter } from "lucide-react";

import { getQuickexApiBase } from "@/lib/api";

type AuditLog = {
  id: string;
  action: string;
  actor: string;
  target?: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
};

type AuditResponse = {
  data: AuditLog[];
};

export function AuditLogs() {
  const apiBase = useMemo(() => getQuickexApiBase(), []);
  const [filter, setFilter] = useState("ALL");
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const response = await fetch(`${apiBase}/admin/audit`, { cache: "no-store" });
        if (!response.ok) {
          throw new Error(`Audit fetch failed (${response.status})`);
        }
        const payload = (await response.json()) as AuditResponse;
        if (!cancelled) {
          setLogs(payload.data ?? []);
          setError(null);
        }
      } catch (fetchError) {
        if (!cancelled) {
          setError(
            fetchError instanceof Error ? fetchError.message : "Unable to load audit logs.",
          );
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [apiBase]);

  const filteredLogs = logs.filter(
    (log) => filter === "ALL" || log.action === filter,
  );
  const actions = ["ALL", ...Array.from(new Set(logs.map((entry) => entry.action)))];

  return (
    <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h2 className="text-lg font-semibold text-gray-800">Audit Logs</h2>
          <p className="text-sm text-gray-500">Feature flag changes are persisted here.</p>
        </div>
        <div className="flex items-center space-x-2">
          <Filter className="h-4 w-4 text-gray-500" />
          <select
            className="border border-gray-200 rounded-md py-1.5 px-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          >
            {actions.map((action) => (
              <option key={action} value={action}>
                {action}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <p className="mb-4 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-700">
          {error}
        </p>
      )}

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
            {filteredLogs.map((log) => (
              <tr key={log.id} className="border-b border-gray-100 last:border-0 hover:bg-gray-50">
                <td className="px-4 py-3 whitespace-nowrap">
                  {new Date(log.createdAt).toLocaleString()}
                </td>
                <td className="px-4 py-3">
                  <span className="bg-gray-100 text-gray-800 px-2 py-1 rounded text-xs font-medium border border-gray-200">
                    {log.action}
                  </span>
                </td>
                <td className="px-4 py-3">{log.actor}</td>
                <td className="px-4 py-3">
                  {log.target ? `${log.target} • ` : ""}
                  {log.metadata?.after && typeof log.metadata.after === "object"
                    ? "Flag state updated"
                    : "Recorded"}
                </td>
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

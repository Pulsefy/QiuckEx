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
    <div className="bg-card p-6 rounded-lg shadow-sm border border-border">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Audit Logs</h2>
          <p className="text-sm text-subtle">Feature flag changes are persisted here.</p>
        </div>
        <div className="flex items-center space-x-2">
          <Filter className="h-4 w-4 text-subtle" />
          <select
            className="border border-border rounded-md py-1.5 px-3 text-sm focus:outline-none focus:ring-2 focus:ring-brand bg-card"
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
        <p className="mb-4 rounded-md border border-warning-soft bg-warning-soft px-3 py-2 text-sm text-warning">
          {error}
        </p>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm text-subtle">
          <thead className="text-xs text-muted uppercase bg-background border-b border-border">
            <tr>
              <th className="px-4 py-3 rounded-tl-lg">Timestamp</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3 rounded-tr-lg">Details</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map((log) => (
              <tr key={log.id} className="border-b border-border last:border-0 hover:bg-background">
                <td className="px-4 py-3 whitespace-nowrap">
                  {new Date(log.createdAt).toLocaleString()}
                </td>
                <td className="px-4 py-3">
                  <span className="bg-surface text-foreground px-2 py-1 rounded text-xs font-medium border border-border">
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
                <td colSpan={4} className="px-4 py-8 text-center text-subtle">
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

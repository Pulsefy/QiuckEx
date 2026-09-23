"use client";

import {
  CheckCircle2,
  FileText,
  Flame,
  ListChecks,
  Timer,
  XCircle,
} from "lucide-react";
import type { SmokeSection } from "@/types/health-console";
import { DataTable, SectionHeader, SectionShell, SummaryCard } from "./SummaryCard";
import {
  EmptyState,
  RowLinks,
  SectionStatusBadge,
  formatDateTime,
  formatSeconds,
  sectionStatusToTone,
  SeverityPill,
  SeverityTone,
} from "./HealthBadges";

function smokeStatusToTone(status: "up" | "down"): SeverityTone {
  return status === "up" ? "success" : "danger";
}

export function SmokeTestPanel({
  data,
  serviceFilter,
  severityFilter,
}: {
  data: SmokeSection;
  serviceFilter: Set<string>;
  severityFilter: Set<string>;
}) {
  const tone = sectionStatusToTone(data.status);
  const total = data.passed + data.failed + (data.skipped ?? 0);

  const rows = data.checks
    .filter((c) => {
      if (serviceFilter.size === 0) return true;
      const category = c.category ?? "health";
      const nameHit = c.name
        .toLowerCase()
        .split(/[-_\s]+/)
        .some((t) => serviceFilter.has(t));
      return serviceFilter.has(category) || serviceFilter.has(c.name) || nameHit;
    })
    .filter((c) => {
      if (severityFilter.size === 0) return true;
      const sev: string = c.status === "down" ? "critical" : "healthy";
      return severityFilter.has(sev);
    })
    .map((c) => {
      const sTone = smokeStatusToTone(c.status);
      return {
        id: `smoke-${c.name}`,
        test: (
          <div className="flex items-center gap-2 min-w-[180px]">
            <div
              className={`h-7 w-7 shrink-0 rounded-md flex items-center justify-center ${
                sTone === "success"
                  ? "bg-success-soft text-success"
                  : "bg-danger-soft text-danger"
              }`}
            >
              {c.status === "up" ? (
                <CheckCircle2 className="h-4 w-4" />
              ) : (
                <XCircle className="h-4 w-4" />
              )}
            </div>
            <div className="min-w-0">
              <div className="font-medium text-foreground">{c.name}</div>
              <div className="text-xs text-faint">
                Category: {(c.category ?? "health").toLowerCase()}
              </div>
            </div>
          </div>
        ),
        result: (
          <SeverityPill
            tone={sTone}
            label={c.status === "up" ? "PASS" : "FAIL"}
            icon={c.status === "up" ? CheckCircle2 : XCircle}
          />
        ),
        duration: (
          <div className="text-sm text-subtle whitespace-nowrap">
            {c.durationMs !== undefined
              ? `${c.durationMs.toLocaleString()} ms`
              : "—"}
          </div>
        ),
        error: c.error ? (
          <div className="text-xs max-w-sm text-danger bg-danger-soft/50 rounded-md border border-danger-soft px-2 py-1.5 whitespace-normal break-words">
            {c.error}
          </div>
        ) : (
          <span className="text-faint text-xs">—</span>
        ),
        lastRun: (
          <div className="text-sm text-subtle whitespace-nowrap">
            {formatDateTime(c.lastRunAt ?? data.lastRunAt)}
          </div>
        ),
        links: (
          <RowLinks
            transaction={c.transactionLink}
            webhook={c.webhookLink}
            registry={undefined}
          />
        ),
      };
    });

  return (
    <SectionShell tone={tone}>
      <SectionHeader
        title="3. Smoke Test Runs"
        description="Latest end-to-end readiness probes. Each check maps to a deep-dependency probe from the readiness subsystem."
        status={data.status}
        right={
          <div className="flex items-center gap-2 flex-wrap justify-end">
            <span className="text-xs text-subtle">
              Last run: {formatDateTime(data.lastRunAt)}
            </span>
            <SectionStatusBadge status={data.status} />
          </div>
        }
      />
      <div className="p-5 space-y-5 border-b border-border">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <SummaryCard
            title="Total Checks"
            value={total}
            subtitle="across all smoke probes"
            tone="gray"
            icon={ListChecks}
          />
          <SummaryCard
            title="Passed"
            value={data.passed}
            subtitle={`${
              total > 0 ? Math.round((data.passed / total) * 100) : 0
            }% success rate`}
            tone="success"
            icon={CheckCircle2}
          />
          <SummaryCard
            title="Failed"
            value={data.failed}
            subtitle={
              data.failed > 0
                ? "Inspect failure details below"
                : "No failed checks"
            }
            tone={data.failed > 0 ? "danger" : "gray"}
            icon={XCircle}
          />
          <SummaryCard
            title="Run Duration"
            value={formatSeconds(
              data.totalDurationMs !== undefined
                ? Math.max(1, Math.round(data.totalDurationMs / 1000))
                : null,
            )}
            subtitle={`${(data.skipped ?? 0) > 0 ? `${data.skipped} skipped` : "no skips"}`}
            tone="brand"
            icon={Timer}
          />
        </div>
        {data.failureDetails && data.failureDetails.length > 0 && (
          <div className="rounded-lg border border-danger-soft bg-danger-soft/40 p-4 space-y-2">
            <div className="flex items-center gap-2 text-sm font-medium text-danger">
              <Flame className="h-4 w-4" />
              Failure Details
            </div>
            <ul className="list-disc pl-5 space-y-1 text-xs text-danger">
              {data.failureDetails.slice(0, 10).map((msg, i) => (
                <li key={i} className="break-words">
                  {msg}
                </li>
              ))}
              {data.failureDetails.length > 10 && (
                <li className="text-faint list-none -ml-1">
                  + {data.failureDetails.length - 10} more
                </li>
              )}
            </ul>
          </div>
        )}
      </div>
      <DataTable
        columns={[
          { key: "test", label: "Smoke Test" },
          { key: "result", label: "Result" },
          { key: "duration", label: "Duration" },
          { key: "error", label: "Failure Detail" },
          { key: "lastRun", label: "Last Run" },
          { key: "links", label: "Go to" },
        ]}
        rows={rows}
        empty={
          <EmptyState
            title="No smoke tests match filters"
            description="Smoke tests are derived from the /ready endpoint deep-dependency checks (Supabase, Horizon, Soroban RPC, queue, migrations, ingestion, environment)."
            icon={FileText}
          />
        }
      />
    </SectionShell>
  );
}

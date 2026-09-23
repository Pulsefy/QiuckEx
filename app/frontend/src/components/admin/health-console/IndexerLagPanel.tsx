"use client";

import {
  Activity,
  Blocks,
  Clock,
  DatabaseZap,
  TimerReset,
  ShieldAlert,
} from "lucide-react";
import type { LagSection } from "@/types/health-console";
import { DataTable, SectionHeader, SectionShell, SummaryCard } from "./SummaryCard";
import {
  EmptyState,
  RowLinks,
  SectionStatusBadge,
  StatusBadge,
  formatDateTime,
  formatNumber,
  formatSeconds,
  sectionStatusToTone,
  severityToTone,
  SeverityPill,
} from "./HealthBadges";

export function IndexerLagPanel({
  data,
  serviceFilter,
  severityFilter,
}: {
  data: LagSection;
  serviceFilter: Set<string>;
  severityFilter: Set<string>;
}) {
  const tone = sectionStatusToTone(data.status);

  const rows = (data.indexerServices ?? [])
    .filter(
      (svc) =>
        serviceFilter.size === 0 || serviceFilter.has(svc.serviceName),
    )
    .filter(
      (svc) =>
        severityFilter.size === 0 || severityFilter.has(svc.severity),
    )
    .map((svc) => {
      const sevTone = severityToTone(svc.severity);
      return {
        id: `idx-${svc.serviceName}`,
        service: (
          <div className="flex items-center gap-2 min-w-[180px]">
            <div
              className={`h-7 w-7 shrink-0 rounded-md flex items-center justify-center ${
                sevTone === "danger"
                  ? "bg-danger-soft text-danger"
                  : sevTone === "warning"
                    ? "bg-warning-soft text-warning"
                    : sevTone === "brand"
                      ? "bg-brand-soft text-brand"
                      : "bg-success-soft text-success"
              }`}
            >
              <DatabaseZap className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <div className="font-medium text-foreground">
                {svc.serviceName}
              </div>
              <div className="text-xs text-faint">
                threshold {formatNumber(svc.thresholdLedgers)} ledgers
              </div>
            </div>
          </div>
        ),
        lag: (
          <div className="space-y-0.5">
            <div
              className={`text-sm font-semibold ${
                sevTone === "danger"
                  ? "text-danger"
                  : sevTone === "warning"
                    ? "text-warning"
                    : "text-foreground"
              }`}
            >
              {formatSeconds(svc.lagSeconds)}
            </div>
            <div className="text-xs text-faint">
              {formatNumber(svc.lagLedgers)} ledgers
            </div>
          </div>
        ),
        ledgers: (
          <div className="space-y-0.5 text-sm text-subtle">
            <div>Network: {formatNumber(svc.currentNetworkLedger)}</div>
            <div>Indexed: {formatNumber(svc.lastIndexedLedger)}</div>
          </div>
        ),
        state: (
          <div className="flex flex-wrap gap-1.5 items-start">
            {svc.isBlocking && (
              <SeverityPill tone="danger" label="Blocking" icon={ShieldAlert} />
            )}
            {!svc.isBlocking && svc.isLagging && (
              <SeverityPill tone="warning" label="Lagging" icon={Activity} />
            )}
            {!svc.isLagging && !svc.isBlocking && (
              <SeverityPill tone="success" label="In sync" icon={Activity} />
            )}
          </div>
        ),
        checkpoint: (
          <div className="text-sm text-subtle whitespace-nowrap">
            {formatDateTime(svc.lastCheckpointAt)}
          </div>
        ),
        severity: <StatusBadge severity={svc.severity} />,
        links: (
          <RowLinks
            transaction={svc.transactionLink}
            webhook={
              svc.serviceName === "webhook-dispatcher"
                ? "/webhooks?service=dispatcher"
                : undefined
            }
            registry={undefined}
          />
        ),
      };
    });

  return (
    <SectionShell tone={tone}>
      <SectionHeader
        title="2. Indexer Lag Metrics"
        description="Per-service ingestion lag measured in ledgers and approximate seconds (5s ledger-close average)."
        status={data.status}
        right={
          <div className="flex items-center gap-2">
            <span className="text-xs text-subtle">
              Threshold: {formatNumber(data.thresholdLedgers)} ledgers
            </span>
            <SectionStatusBadge status={data.status} />
          </div>
        }
      />
      <div className="p-5 space-y-5 border-b border-border">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <SummaryCard
            title="Aggregate Lag"
            value={formatSeconds(data.lagSeconds)}
            subtitle={`${formatNumber(data.lagLedgers)} ledgers behind network`}
            tone={tone}
            icon={Clock}
          />
          <SummaryCard
            title="Network Ledger"
            value={formatNumber(data.currentNetworkLedger)}
            subtitle="Horizon / network head"
            tone="brand"
            icon={Blocks}
          />
          <SummaryCard
            title="Last Indexed"
            value={formatNumber(data.lastIndexedLedger)}
            subtitle="Latest checkpoint written"
            tone="gray"
            icon={TimerReset}
          />
          <SummaryCard
            title="Guard State"
            value={
              data.isBlocking
                ? "Blocking"
                : data.isLagging
                  ? "Permissive"
                  : "Ready"
            }
            subtitle={
              data.isBlocking
                ? "High-lag operations blocked"
                : data.isLagging
                  ? "Guard overridden / disabled"
                  : "All traffic permitted"
            }
            tone={
              data.isBlocking ? "danger" : data.isLagging ? "warning" : "success"
            }
            icon={ShieldAlert}
          />
        </div>
      </div>
      <DataTable
        columns={[
          { key: "service", label: "Indexer Service" },
          { key: "lag", label: "Lag" },
          { key: "ledgers", label: "Ledgers (Network / Indexed)" },
          { key: "state", label: "State" },
          { key: "checkpoint", label: "Last Checkpoint" },
          { key: "severity", label: "Severity" },
          { key: "links", label: "Go to" },
        ]}
        rows={rows}
        empty={
          <EmptyState
            title="No indexer services match filters"
            description="Indexer lag is sampled from Horizon each minute and compared to checkpointed ledgers per ingest pipeline."
            icon={DatabaseZap}
          />
        }
      />
    </SectionShell>
  );
}

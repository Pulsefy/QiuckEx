"use client";

import {
  ClipboardList,
  FileCheck2,
  ShieldX,
  ShieldCheck,
  Boxes,
} from "lucide-react";
import type { RegistrySection } from "@/types/health-console";
import { DataTable, SectionHeader, SectionShell, SummaryCard } from "./SummaryCard";
import {
  EmptyState,
  RowLinks,
  SectionStatusBadge,
  StatusBadge,
  formatDateTime,
  sectionStatusToTone,
  severityToTone,
  SeverityPill,
  truncateHash,
} from "./HealthBadges";

export function RegistryPanel({
  data,
  severityFilter,
}: {
  data: RegistrySection;
  severityFilter: Set<string>;
}) {
  const tone = sectionStatusToTone(data.status);
  const expected = data.expectedContracts.length;
  const active = data.activeContracts;
  const missing = data.missingContracts.length;
  const mismatched = data.mismatchedContracts ?? 0;

  const rows = (data.contractDetails ?? [])
    .filter((c) => severityFilter.size === 0 || severityFilter.has(c.severity))
    .map((c) => {
      const sevTone = severityToTone(c.severity);
      return {
        id: `reg-${c.name}`,
        contract: (
          <div className="flex items-center gap-2 min-w-[160px]">
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
              {c.contractStatus === "missing" ? (
                <ShieldX className="h-4 w-4" />
              ) : (
                <ShieldCheck className="h-4 w-4" />
              )}
            </div>
            <div className="min-w-0">
              <div className="font-medium text-foreground">{c.name}</div>
              <div className="text-xs text-faint">
                {c.networkPassphraseMatches === undefined
                  ? ""
                  : c.networkPassphraseMatches
                    ? "passphrase verified"
                    : "passphrase mismatch"}
              </div>
            </div>
          </div>
        ),
        status: (
          <SeverityPill
            tone={sevTone}
            label={c.contractStatus.charAt(0).toUpperCase() + c.contractStatus.slice(1)}
          />
        ),
        version: (
          <div className="text-sm text-foreground">
            {c.contractVersion !== undefined
              ? `v${c.contractVersion}`
              : "—"}
            {c.schemaVersion ? (
              <span className="text-faint ml-1.5">
                (schema {c.schemaVersion})
              </span>
            ) : null}
          </div>
        ),
        identifiers: (
          <div className="space-y-0.5 font-mono text-xs text-subtle">
            <div>ID: {truncateHash(c.contractId, 6)}</div>
            <div>Wasm: {truncateHash(c.wasmHash, 6)}</div>
          </div>
        ),
        updated: (
          <div className="text-sm text-subtle whitespace-nowrap">
            <div>{formatDateTime(c.updatedAt)}</div>
            {c.publishedBy ? (
              <div className="text-xs text-faint">by {c.publishedBy}</div>
            ) : null}
          </div>
        ),
        severity: <StatusBadge severity={c.severity} />,
        links: (
          <RowLinks
            registry={c.registryLink}
            webhook={c.webhookLink}
            transaction={undefined}
          />
        ),
      };
    });

  return (
    <SectionShell tone={tone}>
      <SectionHeader
        title="1. Contract Registry Status"
        description="Deployed contract health: active entries, missing expected contracts, and passphrase mismatches."
        status={data.status}
        right={
          <div className="flex items-center gap-2">
            <span className="text-xs text-subtle">
              Registry v{data.version} · {data.network}
            </span>
            <SectionStatusBadge status={data.status} />
          </div>
        }
      />
      <div className="p-5 space-y-5 border-b border-border">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <SummaryCard
            title="Expected"
            value={expected}
            subtitle="contracts configured"
            tone="gray"
            icon={Boxes}
          />
          <SummaryCard
            title="Active"
            value={active}
            subtitle={
              data.authoritative ? "authoritative source" : "non-authoritative"
            }
            tone="success"
            icon={FileCheck2}
          />
          <SummaryCard
            title="Missing"
            value={missing}
            subtitle={
              missing > 0 ? "CRITICAL: deploy missing" : "none missing"
            }
            tone={missing > 0 ? "danger" : "gray"}
            icon={ShieldX}
          />
          <SummaryCard
            title="Mismatched"
            value={mismatched}
            subtitle="network passphrase drift"
            tone={mismatched > 0 ? "warning" : "gray"}
            icon={ClipboardList}
          />
        </div>
      </div>
      <DataTable
        columns={[
          { key: "contract", label: "Contract" },
          { key: "status", label: "Status" },
          { key: "version", label: "Version" },
          { key: "identifiers", label: "Contract / Wasm" },
          { key: "updated", label: "Updated" },
          { key: "severity", label: "Severity" },
          { key: "links", label: "Go to" },
        ]}
        rows={rows}
        empty={
          <EmptyState
            title="No registry entries match filters"
            description="Contract detail rows come from the ContractRegistryService and are validated against expected deployment names."
            icon={ClipboardList}
          />
        }
      />
    </SectionShell>
  );
}

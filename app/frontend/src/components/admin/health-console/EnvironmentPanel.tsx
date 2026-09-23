"use client";

import {
  Boxes,
  Calendar,
  GitCommit,
  Globe2,
  Server,
  ShieldCheck,
  Tag,
  XCircle,
  AlertTriangle,
} from "lucide-react";
import type { EnvironmentSection } from "@/types/health-console";
import { DataTable, SectionHeader, SectionShell, SummaryCard } from "./SummaryCard";
import {
  EmptyState,
  SectionStatusBadge,
  StatusBadge,
  formatDateTime,
  formatSeconds,
  sectionStatusToTone,
  severityToTone,
  SeverityPill,
  SeverityTone,
  truncateHash,
} from "./HealthBadges";
import Link from "next/link";

function envStatusToTone(status: "pass" | "fail" | "warning"): SeverityTone {
  switch (status) {
    case "fail":
      return "danger";
    case "warning":
      return "warning";
    default:
      return "success";
  }
}

export function EnvironmentPanel({
  data,
  severityFilter,
}: {
  data: EnvironmentSection;
  severityFilter: Set<string>;
}) {
  const tone = sectionStatusToTone(data.status);
  const meta = data.metadata;

  const rows = data.checks
    .filter((c) => {
      if (severityFilter.size === 0) return true;
      const sev: string =
        c.severity ??
        (c.status === "fail"
          ? "critical"
          : c.status === "warning"
            ? "info"
            : "healthy");
      return severityFilter.has(sev);
    })
    .map((c) => {
      const checkTone = envStatusToTone(c.status);
      const badgeTone: SeverityTone =
        c.severity !== undefined
          ? severityToTone(c.severity)
          : checkTone;
      const StatusIcon =
        c.status === "pass"
          ? ShieldCheck
          : c.status === "fail"
            ? XCircle
            : AlertTriangle;
      return {
        id: `env-${c.check}`,
        check: (
          <div className="flex items-center gap-2 min-w-[200px]">
            <div
              className={`h-7 w-7 shrink-0 rounded-md flex items-center justify-center ${
                checkTone === "danger"
                  ? "bg-danger-soft text-danger"
                  : checkTone === "warning"
                    ? "bg-warning-soft text-warning"
                    : "bg-success-soft text-success"
              }`}
            >
              <StatusIcon className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <div className="font-medium text-foreground break-words">
                {c.check.replace(/_/g, " ")}
              </div>
              {c.details && (
                <div className="text-xs text-subtle break-words max-w-md">
                  {c.details}
                </div>
              )}
            </div>
          </div>
        ),
        status: (
          <SeverityPill
            tone={checkTone}
            label={c.status.charAt(0).toUpperCase() + c.status.slice(1)}
          />
        ),
        severity: <StatusBadge severity={c.severity ?? "healthy"} label="" />,
        details: c.details ? (
          <span className="text-xs text-subtle break-words max-w-sm">
            {c.details}
          </span>
        ) : (
          <span className="text-faint text-xs">—</span>
        ),
        links: c.detailsLink ? (
          <Link
            href={c.detailsLink}
            className="text-xs font-medium text-brand hover:underline"
            target="_blank"
            rel="noreferrer"
          >
            Configure
          </Link>
        ) : (
          <span className="text-faint text-xs">—</span>
        ),
      };
    });

  return (
    <SectionShell tone={tone}>
      <SectionHeader
        title="4. Environment & Deployment Metadata"
        description="App version, commit hash, environment name, and environment-parity checks that catch staging/prod configuration drift."
        status={data.status}
        right={
          <div className="flex items-center gap-2">
            <span className="text-xs text-subtle">
              Parity: {data.passed}/{data.passed + data.failed + data.warnings}
            </span>
            <SectionStatusBadge status={data.status} />
          </div>
        }
      />
      <div className="p-5 space-y-5 border-b border-border">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <SummaryCard
            title="App Version"
            value={meta?.appVersion ?? "—"}
            subtitle={
              meta?.contractRegistryVersion
                ? `registry v${meta.contractRegistryVersion}`
                : undefined
            }
            tone="gray"
            icon={Tag}
          />
          <SummaryCard
            title="Commit"
            value={
              meta?.commitShort ? (
                <span className="font-mono text-xl">
                  {meta.commitShort}
                </span>
              ) : (
                "—"
              )
            }
            subtitle={
              meta?.commitHash ? (
                <span className="font-mono truncate block max-w-full">
                  {truncateHash(meta.commitHash, 10)}
                </span>
              ) : undefined
            }
            tone="brand"
            icon={GitCommit}
          />
          <SummaryCard
            title="Environment"
            value={meta?.environmentName ?? "—"}
            subtitle={`Network: ${meta?.network ?? "unknown"}`}
            tone={
              (meta?.network ?? "").toLowerCase() === "mainnet"
                ? "danger"
                : (meta?.network ?? "").toLowerCase() === "testnet"
                  ? "warning"
                  : "success"
            }
            icon={Globe2}
          />
          <SummaryCard
            title="Uptime"
            value={formatSeconds(meta?.uptimeSeconds ?? null)}
            subtitle={
              meta?.deployedAt
                ? `deployed ${formatDateTime(meta.deployedAt)}`
                : meta?.nodeEnv
                  ? `NODE_ENV=${meta.nodeEnv}`
                  : undefined
            }
            tone="success"
            icon={Server}
          />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
          <SummaryCard
            title="Parity Passed"
            value={data.passed}
            tone="success"
            icon={Boxes}
          />
          <SummaryCard
            title="Parity Failed"
            value={data.failed}
            tone={data.failed > 0 ? "danger" : "gray"}
            icon={XCircle}
          />
          <SummaryCard
            title="Parity Warnings"
            value={data.warnings}
            tone={data.warnings > 0 ? "warning" : "gray"}
            icon={AlertTriangle}
          />
          <SummaryCard
            title="Deployed At"
            value={
              meta?.deployedAt ? (
                <span className="text-base font-bold">
                  {formatDateTime(meta.deployedAt)}
                </span>
              ) : (
                "—"
              )
            }
            tone="brand"
            icon={Calendar}
          />
        </div>
      </div>
      <DataTable
        columns={[
          { key: "check", label: "Parity Check" },
          { key: "status", label: "Status" },
          { key: "severity", label: "Severity" },
          { key: "details", label: "Details" },
          { key: "links", label: "Go to" },
        ]}
        rows={rows}
        empty={
          <EmptyState
            title="No parity checks match filters"
            description="Environment-parity checks run on module init and compare staging configuration to production baselines."
            icon={Server}
          />
        }
      />
    </SectionShell>
  );
}

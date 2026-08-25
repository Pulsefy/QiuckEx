"use client";

import Link from "next/link";
import type { ComponentType, ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  XCircle,
} from "lucide-react";

import type {
  ContractDeploymentItem,
  RcEnvironmentSection,
  RcLagSection,
  RcRegistrySection,
  RcSectionStatus,
  RcSmokeCheck,
  RcSmokeSection,
} from "./testnet-health.types";

export function stellarExpertContractUrl(
  network: string,
  contractId: string,
): string {
  return `https://stellar.expert/explorer/${network}/contract/${contractId}`;
}

const SECTION_PILL_CLASSES: Record<RcSectionStatus, string> = {
  pass: "bg-success-soft text-success border border-success",
  warning: "bg-warning-soft text-warning border border-warning",
  fail: "bg-danger-soft text-danger border border-danger",
  unknown: "bg-surface text-subtle border border-border-strong",
};

const SECTION_PILL_LABEL: Record<RcSectionStatus, string> = {
  pass: "Healthy",
  warning: "Warning",
  fail: "Failing",
  unknown: "Unknown",
};

export const SECTION_SEVERITY: Record<
  RcSectionStatus,
  "critical" | "warning" | "info" | "none"
> = {
  pass: "none",
  warning: "warning",
  fail: "critical",
  unknown: "warning",
};

interface SectionCardProps {
  id: string;
  title: string;
  description: string;
  status: RcSectionStatus;
  icon: ComponentType<{ className?: string }>;
  dimmed?: boolean;
  headerExtra?: ReactNode;
  footerLinks?: ReactNode;
  children: ReactNode;
}

function SectionCard({
  id,
  title,
  description,
  status,
  icon: Icon,
  dimmed = false,
  headerExtra,
  footerLinks,
  children,
}: SectionCardProps) {
  return (
    <section
      id={id}
      aria-label={title}
      className={`bg-card p-6 rounded-lg shadow-sm border border-border transition-opacity scroll-mt-24 ${
        dimmed ? "opacity-40" : ""
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Icon className="h-5 w-5 text-brand" />
            <h3 className="text-base font-semibold text-foreground">{title}</h3>
            <span
              className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${SECTION_PILL_CLASSES[status]}`}
            >
              {SECTION_PILL_LABEL[status]}
            </span>
          </div>
          <p className="mt-1 text-xs text-subtle">{description}</p>
        </div>
        {headerExtra}
      </div>
      {children}
      {footerLinks && (
        <div className="mt-4 flex flex-wrap gap-4 border-t border-border pt-3">
          {footerLinks}
        </div>
      )}
    </section>
  );
}

export function CardFooterLink({
  href,
  children,
  external = false,
}: {
  href: string;
  children: ReactNode;
  external?: boolean;
}) {
  const classes =
    "inline-flex items-center gap-1 text-sm font-medium text-brand hover:underline";
  if (external) {
    return (
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className={classes}
      >
        {children}
        <ArrowUpRight className="h-3.5 w-3.5" />
      </a>
    );
  }
  return (
    <Link href={href} className={classes}>
      {children}
      <ArrowUpRight className="h-3.5 w-3.5" />
    </Link>
  );
}

function StatTile({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  tone?: "neutral" | "success" | "warning" | "danger";
}) {
  const toneClasses = {
    neutral: "text-foreground",
    success: "text-success",
    warning: "text-warning",
    danger: "text-danger",
  }[tone];
  return (
    <div className="rounded-md border border-border bg-background px-3 py-2">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-subtle">
        {label}
      </p>
      <p className={`text-lg font-bold ${toneClasses}`}>{value}</p>
    </div>
  );
}

export function RegistryStatusCard({
  section,
  deployments,
  deploymentsError,
  dimmed = false,
}: {
  section: RcRegistrySection;
  deployments: ContractDeploymentItem[];
  deploymentsError?: string | null;
  dimmed?: boolean;
}) {
  return (
    <SectionCard
      id="th-registry"
      title="Contract Registry"
      description={`Active Soroban contract deployments on ${section.network}.`}
      status={section.status}
      icon={CheckCircle2}
      dimmed={dimmed}
      footerLinks={
        <CardFooterLink href="/webhooks">Webhook delivery logs</CardFooterLink>
      }
    >
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        <StatTile label="Active" value={section.activeContracts} />
        <StatTile label="Expected" value={section.expectedContracts.length} />
        <StatTile
          label="Missing"
          value={section.missingContracts.length}
          tone={section.missingContracts.length > 0 ? "danger" : "success"}
        />
        <StatTile label="Version" value={section.version} />
      </div>

      {!section.authoritative && (
        <p className="mb-3 rounded-md border border-warning bg-warning-soft px-3 py-2 text-xs text-warning">
          Registry is not marked authoritative — dual-read is still active.
        </p>
      )}

      {section.missingContracts.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <span className="text-xs text-subtle">Missing:</span>
          {section.missingContracts.map((name) => (
            <span
              key={name}
              className="rounded-full bg-danger-soft px-2 py-0.5 text-[11px] font-semibold text-danger"
            >
              {name}
            </span>
          ))}
        </div>
      )}

      {deploymentsError ? (
        <p className="rounded-md border border-warning bg-warning-soft px-3 py-2 text-xs text-warning">
          {deploymentsError}
        </p>
      ) : deployments.length === 0 ? (
        <p className="py-3 text-center text-sm text-subtle">
          No active deployments published for this network.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-muted">
            <thead className="text-xs uppercase bg-background border-b border-border text-subtle">
              <tr>
                <th className="px-3 py-2 rounded-tl-lg">Contract</th>
                <th className="px-3 py-2">Contract ID</th>
                <th className="px-3 py-2">Ver</th>
                <th className="px-3 py-2">Schema</th>
                <th className="px-3 py-2 rounded-tr-lg">Updated</th>
              </tr>
            </thead>
            <tbody>
              {deployments.map((deployment) => (
                <tr
                  key={`${deployment.name}-${deployment.contractId}`}
                  className="border-b border-border last:border-0 hover:bg-background"
                >
                  <td className="px-3 py-2 font-medium text-foreground whitespace-nowrap">
                    {deployment.name}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">
                    <a
                      href={stellarExpertContractUrl(
                        deployment.network || section.network,
                        deployment.contractId,
                      )}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-brand hover:underline"
                      title={deployment.contractId}
                    >
                      {deployment.contractId.slice(0, 12)}…
                      <ArrowUpRight className="h-3 w-3" />
                    </a>
                  </td>
                  <td className="px-3 py-2">{deployment.contractVersion}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {deployment.schemaVersion}
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap text-xs text-subtle">
                    {new Date(deployment.updatedAt).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  );
}

export function IndexerLagCard({
  section,
  dimmed = false,
}: {
  section: RcLagSection;
  dimmed?: boolean;
}) {
  const lag = section.lagLedgers;
  const threshold = Math.max(1, section.thresholdLedgers);
  const ratio = lag === null ? 0 : Math.min(1, lag / threshold);
  const barClasses =
    section.isBlocking || section.status === "fail"
      ? "bg-danger"
      : section.isLagging || section.status === "warning"
        ? "bg-warning"
        : "bg-success";

  return (
    <SectionCard
      id="th-lag"
      title="Indexer Lag"
      description="Ingestion checkpoint vs. Stellar network head."
      status={section.status}
      icon={Activity}
      dimmed={dimmed}
      footerLinks={
        <CardFooterLink href="/dashboard">Recent transactions</CardFooterLink>
      }
    >
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        <StatTile
          label="Lag"
          value={lag === null ? "—" : `${lag}`}
          tone={
            section.isBlocking
              ? "danger"
              : section.isLagging
                ? "warning"
                : "success"
          }
        />
        <StatTile label="Threshold" value={section.thresholdLedgers} />
        <StatTile
          label="Network head"
          value={section.currentNetworkLedger ?? "—"}
        />
        <StatTile label="Last indexed" value={section.lastIndexedLedger ?? "—"} />
      </div>

      <div
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={threshold}
        aria-valuenow={lag ?? undefined}
        aria-label="Indexer lag vs threshold"
        className="h-2 w-full overflow-hidden rounded-full bg-surface"
      >
        <div
          className={`h-full rounded-full transition-all ${barClasses}`}
          style={{ width: `${Math.round(ratio * 100)}%` }}
        />
      </div>
      <p className="mt-2 text-xs text-subtle">
        {section.isBlocking
          ? "Lag guard is blocking traffic until ingestion catches up."
          : section.isLagging
            ? "Indexer is behind threshold but the guard is not enforcing."
            : lag === null
              ? "Waiting for ledger data from Horizon and checkpoints."
              : "Indexer is keeping up with the network head."}
      </p>
    </SectionCard>
  );
}

export function SmokeRunsCard({
  section,
  dimmed = false,
}: {
  section: RcSmokeSection;
  dimmed?: boolean;
}) {
  const checkPill = (status: RcSmokeCheck["status"]) => {
    if (status === "up")
      return "bg-success-soft text-success border border-success";
    if (status === "degraded")
      return "bg-warning-soft text-warning border border-warning";
    return "bg-danger-soft text-danger border border-danger";
  };

  return (
    <SectionCard
      id="th-smoke"
      title="Smoke Runs"
      description="Deep readiness probes across critical dependencies."
      status={section.status}
      icon={section.ready ? CheckCircle2 : XCircle}
      headerExtra={
        <span
          className={`rounded-full px-3 py-1 text-xs font-semibold ${
            section.ready
              ? "bg-success-soft text-success"
              : "bg-danger-soft text-danger"
          }`}
        >
          {section.ready ? "Ready" : "Not ready"}
        </span>
      }
      dimmed={dimmed}
      footerLinks={
        <CardFooterLink href="/dashboard">Recent transactions</CardFooterLink>
      }
    >
      <div className="grid grid-cols-2 gap-3 mb-4">
        <StatTile
          label="Passed"
          value={section.passed}
          tone={section.passed > 0 ? "success" : "neutral"}
        />
        <StatTile
          label="Failed"
          value={section.failed}
          tone={section.failed > 0 ? "danger" : "success"}
        />
      </div>

      {section.checks.length === 0 ? (
        <p className="py-3 text-center text-sm text-subtle">
          No smoke checks reported yet.
        </p>
      ) : (
        <ul className="space-y-2">
          {section.checks.map((check) => (
            <li
              key={check.name}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border px-3 py-2"
            >
              <span className="font-mono text-xs font-medium text-foreground">
                {check.name}
              </span>
              <span className="flex items-center gap-2">
                {check.error && (
                  <span
                    className="max-w-[16rem] truncate text-xs text-danger"
                    title={check.error}
                  >
                    {check.error}
                  </span>
                )}
                <span
                  className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${checkPill(
                    check.status,
                  )}`}
                >
                  {check.status}
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  );
}

export function EnvironmentMetaCard({
  network,
  environment,
  generatedAt,
  releaseReady,
  section,
  dimmed = false,
}: {
  network: string;
  environment: string;
  generatedAt: string;
  releaseReady: boolean;
  section: RcEnvironmentSection;
  dimmed?: boolean;
}) {
  return (
    <SectionCard
      id="th-environment"
      title="Environment Metadata"
      description="Deployment context and staging/prod parity checks."
      status={section.status}
      icon={AlertTriangle}
      dimmed={dimmed}
    >
      <dl className="mb-4 grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
        <div>
          <dt className="text-[11px] font-semibold uppercase tracking-wide text-subtle">
            Network
          </dt>
          <dd className="font-medium capitalize text-foreground">{network}</dd>
        </div>
        <div>
          <dt className="text-[11px] font-semibold uppercase tracking-wide text-subtle">
            Environment
          </dt>
          <dd className="font-medium capitalize text-foreground">
            {environment}
          </dd>
        </div>
        <div>
          <dt className="text-[11px] font-semibold uppercase tracking-wide text-subtle">
            Generated
          </dt>
          <dd className="font-medium text-foreground">
            {new Date(generatedAt).toLocaleString()}
          </dd>
        </div>
        <div>
          <dt className="text-[11px] font-semibold uppercase tracking-wide text-subtle">
            Release ready
          </dt>
          <dd
            className={`font-semibold ${
              releaseReady ? "text-success" : "text-danger"
            }`}
          >
            {releaseReady ? "Yes" : "No"}
          </dd>
        </div>
      </dl>

      {section.checks.length === 0 ? (
        <p className="py-3 text-center text-sm text-subtle">
          No parity checks reported.
        </p>
      ) : (
        <ul className="space-y-2">
          {section.checks.map((check) => {
            const tone =
              check.status === "pass"
                ? "bg-success-soft text-success border border-success"
                : check.status === "warning"
                  ? "bg-warning-soft text-warning border border-warning"
                  : "bg-danger-soft text-danger border border-danger";
            return (
              <li
                key={check.check}
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border px-3 py-2"
              >
                <span className="font-mono text-xs font-medium text-foreground">
                  {check.check}
                </span>
                <span className="flex items-center gap-2">
                  {check.details && (
                    <span
                      className="max-w-[16rem] truncate text-xs text-subtle"
                      title={check.details}
                    >
                      {check.details}
                    </span>
                  )}
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${tone}`}
                  >
                    {check.status}
                  </span>
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </SectionCard>
  );
}

"use client";

import Link from "next/link";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  ExternalLink,
  Info,
  Link as LinkIcon,
  Loader2,
  ShieldAlert,
} from "lucide-react";
import type {
  OverallStatus,
  SectionStatus,
  Severity,
} from "@/types/health-console";

export type SeverityTone = "danger" | "warning" | "brand" | "success" | "gray";

export function severityToTone(severity?: Severity | null): SeverityTone {
  switch (severity) {
    case "critical":
      return "danger";
    case "warning":
      return "warning";
    case "info":
      return "brand";
    case "healthy":
      return "success";
    default:
      return "gray";
  }
}

export function sectionStatusToTone(
  status?: SectionStatus | null,
): SeverityTone {
  switch (status) {
    case "fail":
      return "danger";
    case "warning":
      return "warning";
    case "pass":
      return "success";
    case "unknown":
      return "gray";
    default:
      return "gray";
  }
}

export function overallStatusToTone(
  status?: OverallStatus | null,
): SeverityTone {
  switch (status) {
    case "blocked":
      return "danger";
    case "degraded":
      return "warning";
    case "ready":
      return "success";
    default:
      return "gray";
  }
}

export function overallStatusLabel(status: OverallStatus): string {
  switch (status) {
    case "blocked":
      return "Not Ready";
    case "degraded":
      return "Degraded";
    case "ready":
      return "Ready";
  }
}

const TONE_STYLES: Record<
  SeverityTone,
  {
    pill: string;
    dot: string;
    softBg: string;
    softBorder: string;
    text: string;
    icon: typeof CheckCircle2;
  }
> = {
  danger: {
    pill: "bg-danger-soft text-danger border-danger-soft",
    dot: "bg-danger",
    softBg: "bg-danger-soft",
    softBorder: "border-danger-soft",
    text: "text-danger",
    icon: ShieldAlert,
  },
  warning: {
    pill: "bg-warning-soft text-warning border-warning-soft",
    dot: "bg-warning",
    softBg: "bg-warning-soft",
    softBorder: "border-warning-soft",
    text: "text-warning",
    icon: AlertTriangle,
  },
  brand: {
    pill: "bg-brand-soft text-brand border-brand-soft",
    dot: "bg-brand",
    softBg: "bg-brand-soft",
    softBorder: "border-brand-soft",
    text: "text-brand",
    icon: Info,
  },
  success: {
    pill: "bg-success-soft text-success border-success-soft",
    dot: "bg-success",
    softBg: "bg-success-soft",
    softBorder: "border-success-soft",
    text: "text-success",
    icon: CheckCircle2,
  },
  gray: {
    pill: "bg-surface text-muted border-border",
    dot: "bg-faint",
    softBg: "bg-surface",
    softBorder: "border-border",
    text: "text-subtle",
    icon: AlertCircle,
  },
};

export function SeverityDot({
  tone,
  className = "",
}: {
  tone: SeverityTone;
  className?: string;
}) {
  const s = TONE_STYLES[tone];
  return (
    <span
      aria-hidden
      className={`inline-block h-2.5 w-2.5 rounded-full ring-2 ring-offset-2 ring-offset-card ${s.dot} opacity-90 ${className}`}
    />
  );
}

export function SeverityPill({
  label,
  tone,
  icon,
  className = "",
}: {
  label: string;
  tone: SeverityTone;
  icon?: React.ComponentType<{ className?: string }>;
  className?: string;
}) {
  const s = TONE_STYLES[tone];
  const Icon = icon ?? s.icon;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${s.pill} ${className}`}
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
    </span>
  );
}

export function StatusBadge({
  severity,
  label,
}: {
  severity: Severity;
  label?: string;
}) {
  const tone = severityToTone(severity);
  const labelText = label ?? severity.toUpperCase();
  return <SeverityPill tone={tone} label={labelText} />;
}

export function SectionStatusBadge({
  status,
}: {
  status: SectionStatus;
}) {
  const tone = sectionStatusToTone(status);
  const label =
    status === "pass"
      ? "Healthy"
      : status === "fail"
        ? "Failed"
        : status === "warning"
          ? "Warning"
          : "Unknown";
  return <SeverityPill tone={tone} label={label} />;
}

export function LoadingSkeleton({
  label = "Loading health data...",
}: {
  label?: string;
}) {
  return (
    <div className="flex items-center justify-center gap-3 rounded-lg border border-border bg-card px-6 py-12 text-subtle">
      <Loader2 className="h-5 w-5 animate-spin text-brand" />
      <span className="text-sm">{label}</span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  icon: Icon = Activity,
}: {
  title: string;
  description?: string;
  icon?: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-surface px-6 py-10 text-center">
      <Icon className="h-8 w-8 text-faint" />
      <p className="font-medium text-foreground">{title}</p>
      {description && (
        <p className="text-sm text-subtle max-w-md">{description}</p>
      )}
    </div>
  );
}

export function ErrorState({
  title = "Unable to load data",
  message,
  onRetry,
}: {
  title?: string;
  message?: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-danger-soft bg-danger-soft/40 px-6 py-10 text-center">
      <AlertCircle className="h-8 w-8 text-danger" />
      <div className="space-y-1">
        <p className="font-medium text-foreground">{title}</p>
        {message && <p className="text-sm text-subtle max-w-md">{message}</p>}
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-sm font-medium text-foreground hover:bg-surface"
        >
          <Clock className="h-4 w-4" />
          Retry
        </button>
      )}
    </div>
  );
}

export function RowLinks({
  transaction,
  webhook,
  registry,
}: {
  transaction?: string;
  webhook?: string;
  registry?: string;
}) {
  const items: Array<{ href: string; label: string; Icon: typeof LinkIcon }> =
    [];
  if (transaction)
    items.push({
      href: transaction,
      label: "Transactions",
      Icon: ArrowRight,
    });
  if (webhook)
    items.push({ href: webhook, label: "Webhooks", Icon: LinkIcon });
  if (registry)
    items.push({ href: registry, label: "Registry", Icon: ExternalLink });

  if (items.length === 0) {
    return <span className="text-faint text-xs">—</span>;
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      {items.map(({ href, label, Icon }) => (
        <Link
          key={href}
          href={href}
          className="inline-flex items-center gap-1 text-xs font-medium text-brand hover:underline"
          target="_blank"
          rel="noreferrer"
        >
          <Icon className="h-3 w-3" />
          {label}
        </Link>
      ))}
    </div>
  );
}

export function formatSeconds(seconds?: number | null): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds))
    return "—";
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return s > 0 ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm > 0 ? `${h}h ${rm}m` : `${h}h`;
}

export function formatNumber(value?: number | null): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toLocaleString();
}

export function formatDateTime(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}

export function truncateHash(hash?: string | null, keep = 8): string {
  if (!hash) return "—";
  if (hash.length <= keep * 2 + 3) return hash;
  return `${hash.slice(0, keep)}…${hash.slice(-keep)}`;
}

export function toneBorder(tone: SeverityTone): string {
  return TONE_STYLES[tone].softBorder;
}

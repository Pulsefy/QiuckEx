"use client";

import type { ReactNode } from "react";
import {
  SeverityDot,
  SeverityTone,
  sectionStatusToTone,
  toneBorder,
} from "./HealthBadges";
import type { SectionStatus } from "@/types/health-console";

export function SummaryCard({
  title,
  value,
  subtitle,
  tone,
  icon: Icon,
  action,
  className = "",
}: {
  title: string;
  value: ReactNode;
  subtitle?: ReactNode;
  tone: SeverityTone;
  icon: React.ComponentType<{ className?: string }>;
  action?: ReactNode;
  className?: string;
}) {
  const toneStyles = {
    danger: {
      text: "text-danger",
      soft: "bg-danger-soft",
      border: "border-danger-soft",
    },
    warning: {
      text: "text-warning",
      soft: "bg-warning-soft",
      border: "border-warning-soft",
    },
    brand: {
      text: "text-brand",
      soft: "bg-brand-soft",
      border: "border-brand-soft",
    },
    success: {
      text: "text-success",
      soft: "bg-success-soft",
      border: "border-success-soft",
    },
    gray: {
      text: "text-subtle",
      soft: "bg-surface",
      border: "border-border",
    },
  }[tone];

  return (
    <div
      className={`relative overflow-hidden rounded-lg border bg-card p-4 shadow-sm ${toneStyles.border} ${className}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div
            className={`flex items-center gap-2 text-xs font-medium uppercase tracking-wide ${toneStyles.text}`}
          >
            <Icon className="h-4 w-4" />
            <span>{title}</span>
          </div>
          <div className="mt-2 text-2xl font-bold text-foreground leading-tight">
            {value}
          </div>
          {subtitle !== undefined && subtitle !== null && subtitle !== "" && (
            <div className="mt-1 text-xs text-subtle break-words">
              {subtitle}
            </div>
          )}
        </div>
        <div className="shrink-0 flex flex-col items-end gap-2">
          <SeverityDot tone={tone} />
          {action}
        </div>
      </div>
    </div>
  );
}

export function SectionHeader({
  title,
  description,
  status,
  right,
}: {
  title: string;
  description?: string;
  status: SectionStatus;
  right?: ReactNode;
}) {
  const tone = sectionStatusToTone(status);
  return (
    <div
      className={`flex flex-wrap items-start justify-between gap-3 rounded-t-lg border border-b-0 bg-card/50 px-5 py-4 ${toneBorder(tone)}`}
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <h3 className="text-base font-semibold text-foreground">{title}</h3>
        </div>
        {description && (
          <p className="mt-1 text-xs text-subtle max-w-2xl">{description}</p>
        )}
      </div>
      <div className="flex items-center gap-2 shrink-0">{right}</div>
    </div>
  );
}

export function SectionShell({
  children,
  tone,
}: {
  children: ReactNode;
  tone: SeverityTone;
}) {
  return (
    <div
      className={`overflow-hidden rounded-lg border bg-card shadow-sm ${toneBorder(tone)}`}
    >
      {children}
    </div>
  );
}

export function DataTable({
  columns,
  rows,
  empty,
  loading,
}: {
  columns: Array<{ key: string; label: string; align?: "left" | "right" }>;
  rows: Array<Record<string, unknown> & { id?: string }>;
  empty: ReactNode;
  loading?: boolean;
}) {
  if (loading) {
    return (
      <div className="px-5 py-12 text-center text-subtle text-sm">
        Loading table rows...
      </div>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="bg-background/60 text-xs uppercase tracking-wide text-subtle border-b border-border">
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                className={`px-5 py-3 font-medium ${
                  col.align === "right" ? "text-right" : "text-left"
                }`}
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-5 py-10">
                {empty}
              </td>
            </tr>
          ) : (
            rows.map((row, idx) => (
              <tr
                key={row.id ?? String(idx)}
                className="hover:bg-background/50 transition-colors"
              >
                {columns.map((col) => (
                  <td
                    key={col.key}
                    className={`px-5 py-3 align-middle ${
                      col.align === "right" ? "text-right" : "text-left"
                    }`}
                  >
                    {row[col.key] as ReactNode}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

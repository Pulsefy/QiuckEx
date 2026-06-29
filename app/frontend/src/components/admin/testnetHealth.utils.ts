export type Severity = "critical" | "warning" | "info";
export type SectionStatus = "pass" | "warning" | "fail" | "unknown";

export function getSeverityTone(severity: Severity) {
  switch (severity) {
    case "critical":
      return "border-danger/40 bg-danger/10 text-danger";
    case "warning":
      return "border-warning/40 bg-warning/10 text-warning";
    default:
      return "border-info/40 bg-info/10 text-info";
  }
}

export function getSectionTone(status: SectionStatus) {
  switch (status) {
    case "pass":
      return "border-success/40 bg-success/10 text-success";
    case "warning":
      return "border-warning/40 bg-warning/10 text-warning";
    case "fail":
      return "border-danger/40 bg-danger/10 text-danger";
    default:
      return "border-slate-200 bg-slate-50 text-slate-600";
  }
}

export function summarizeReport(report: {
  releaseReady?: boolean;
  overallStatus?: string;
  summary?: { critical?: number; warning?: number; info?: number };
}) {
  const overall = report.releaseReady === false || report.overallStatus === "blocked"
    ? "Blocked"
    : report.overallStatus === "degraded"
      ? "Degraded"
      : "Ready";

  const blocks = (report.summary?.critical ?? 0) + (report.summary?.warning ?? 0) + (report.summary?.info ?? 0);

  return {
    overall,
    blocks,
  };
}

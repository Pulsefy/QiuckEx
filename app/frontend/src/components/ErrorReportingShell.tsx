"use client";

import { useState } from "react";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { ReportIssueModal } from "@/components/ReportIssueModal";
import {
  RequestContextProvider,
  useRequestContext,
} from "@/lib/requestContext";
import { errorReporter } from "@/lib/errorReporter";

type ErrorReportingShellProps = {
  children: React.ReactNode;
};

type ReportPayload = {
  userMessage?: string;
};

function ErrorReportingShellContent({ children }: ErrorReportingShellProps) {
  const { requestId, correlationId } = useRequestContext();
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [activeError, setActiveError] = useState<Error | null>(null);
  const [activeSummary, setActiveSummary] = useState("");

  const openReportModal = (error: Error, componentStack?: string) => {
    setActiveError(error);
    setActiveSummary(componentStack ?? error.message);
    setIsModalOpen(true);
  };

  const closeReportModal = () => {
    setIsModalOpen(false);
    setActiveError(null);
    setActiveSummary("");
  };

  const handleModalSubmit = async ({ userMessage }: ReportPayload) => {
    if (!activeError) {
      return;
    }

    await errorReporter.captureError(activeError, {
      requestId,
      correlationId,
      route: typeof window !== "undefined" ? window.location.pathname : undefined,
      componentStack: activeError.stack,
      extra: {
        userMessage,
        source: "report-issue-modal",
      },
    });
  };

  return (
    <>
      <ErrorBoundary onOpenReportIssue={openReportModal}>
        {children}
      </ErrorBoundary>
      <ReportIssueModal
        open={isModalOpen}
        onClose={closeReportModal}
        errorSummary={activeSummary}
        requestId={requestId}
        onSubmit={handleModalSubmit}
      />
    </>
  );
}

export function ErrorReportingShell({ children }: ErrorReportingShellProps) {
  return (
    <RequestContextProvider>
      <ErrorReportingShellContent>{children}</ErrorReportingShellContent>
    </RequestContextProvider>
  );
}

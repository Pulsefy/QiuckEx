"use client";

import { Component, type ErrorInfo } from "react";
import { errorReporter } from "@/lib/errorReporter";
import { RequestContext, type RequestContextValue } from "@/lib/requestContext";

type ErrorBoundaryProps = {
  children: React.ReactNode;
  onOpenReportIssue?: (error: Error, componentStack?: string) => void;
};

type ErrorBoundaryState = {
  hasError: boolean;
  error?: Error;
  componentStack?: string;
};

export class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  static contextType = RequestContext;
  declare context: RequestContextValue | null;

  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: undefined,
      componentStack: undefined,
    };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    const capturedError = error instanceof Error ? error : new Error(String(error));

    this.setState({
      hasError: true,
      error: capturedError,
      componentStack: info.componentStack ?? undefined,
    });

    errorReporter.captureError(capturedError, {
      requestId: this.context?.requestId,
      correlationId: this.context?.correlationId,
      route: typeof window !== "undefined" ? window.location.pathname : undefined,
      componentStack: info.componentStack ?? undefined,
    });
  }

  handleReportClick = () => {
    if (!this.state.error) {
      return;
    }

    this.props.onOpenReportIssue?.(
      this.state.error,
      this.state.componentStack
    );
  };

  render() {
    if (this.state.hasError) {
      return (
        <section className="mx-auto flex min-h-[60vh] max-w-3xl flex-col items-center justify-center gap-6 rounded-3xl border border-white/10 bg-neutral-950/90 p-8 text-center shadow-2xl shadow-black/20">
          <p className="text-sm uppercase tracking-[0.22em] text-neutral-400">
            Something went wrong
          </p>
          <h1 className="text-3xl font-semibold text-white">An error occurred</h1>
          <p className="max-w-xl text-neutral-300">
            This issue has been captured and can be reported with your request details.
          </p>
          <button
            type="button"
            onClick={this.handleReportClick}
            className="rounded-full bg-white px-6 py-3 text-sm font-semibold text-neutral-950 transition hover:bg-neutral-100"
          >
            Report Issue
          </button>
        </section>
      );
    }

    return this.props.children;
  }
}

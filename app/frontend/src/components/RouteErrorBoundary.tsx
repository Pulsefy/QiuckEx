"use client";

import { Component, type ErrorInfo } from "react";
import Link from "next/link";
import { errorReporter } from "@/lib/errorReporter";

type RouteErrorBoundaryProps = {
  children: React.ReactNode;
  /** The route segment name shown in the fallback UI (e.g. "Dashboard") */
  routeLabel: string;
  /** Optional URL for a support/contact reference on payment/receipt routes */
  supportReference?: string;
};

type RouteErrorBoundaryState = {
  hasError: boolean;
  error?: Error;
};

/**
 * Shared class-based error boundary used by Next.js `error.tsx` files.
 *
 * Responsibilities:
 * 1. Catch render errors and display a recoverable UI (retry + home link).
 * 2. Report the error to the existing errorReporter with route context.
 * 3. Never expose raw stack traces to the user.
 * 4. Surface a support reference on payment / receipt routes.
 */
export class RouteErrorBoundary extends Component<
  RouteErrorBoundaryProps,
  RouteErrorBoundaryState
> {
  constructor(props: RouteErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: undefined };
  }

  static getDerivedStateFromError(error: Error): RouteErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    const capturedError = error instanceof Error ? error : new Error(String(error));

    // Report to existing error reporter with route context
    void errorReporter.captureError(capturedError, {
      route: typeof window !== "undefined" ? window.location.pathname : undefined,
      componentStack: info.componentStack ?? undefined,
      extra: {
        source: "route-error-boundary",
        routeLabel: this.props.routeLabel,
      },
    });
  }

  render() {
    if (this.state.hasError) {
      return (
        <section className="mx-auto flex min-h-[50vh] max-w-2xl flex-col items-center justify-center gap-6 rounded-3xl border border-border-strong bg-background/90 p-8 text-center shadow-2xl shadow-black/20">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-red-500/10">
            <svg
              className="h-8 w-8 text-danger"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={1.5}
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"
              />
            </svg>
          </div>

          <p className="text-sm uppercase tracking-[0.22em] text-subtle">
            {this.props.routeLabel}
          </p>
          <h2 className="text-2xl font-semibold text-foreground">
            Something went wrong
          </h2>
          <p className="max-w-md text-sm text-muted">
            This issue has been reported automatically. You can try again or
            return to a safe page.
          </p>

          {this.props.supportReference && (
            <p className="max-w-md rounded-2xl border border-amber-300/30 bg-amber-400/5 px-4 py-3 text-sm text-amber-700 dark:text-amber-400">
              If this involves a payment or receipt, please contact{" "}
              <a
                href={this.props.supportReference}
                target="_blank"
                rel="noopener noreferrer"
                className="underline underline-offset-2 transition hover:text-amber-900 dark:hover:text-amber-300"
              >
                support
              </a>{" "}
              and quote your request details.
            </p>
          )}

          <div className="flex items-center gap-4">
            <button
              type="button"
              onClick={() => {
                this.setState({ hasError: false, error: undefined });
                // Next.js `reset` is passed via the error.tsx wrapper —
                // this click handler is a fallback that re-renders children.
                if (typeof window !== "undefined") {
                  window.location.reload();
                }
              }}
              className="rounded-xl bg-indigo-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg transition hover:bg-indigo-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2"
            >
              Try again
            </button>
            <Link
              href="/"
              className="rounded-xl border border-border bg-surface px-5 py-2.5 text-sm font-semibold text-foreground transition hover:bg-surface-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2"
            >
              Go to homepage
            </Link>
          </div>
        </section>
      );
    }

    return this.props.children;
  }
}

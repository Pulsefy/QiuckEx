"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { redactPII } from "@/lib/errorReporter";

type ReportIssueModalProps = {
  open: boolean;
  onClose: () => void;
  errorSummary: string;
  requestId?: string;
  onSubmit: (payload: { userMessage?: string }) => Promise<void> | void;
};

export function ReportIssueModal({
  open,
  onClose,
  errorSummary,
  requestId,
  onSubmit,
}: ReportIssueModalProps) {
  const [userMessage, setUserMessage] = useState("");
  const [status, setStatus] = useState<"idle" | "submitting" | "success">(
    "idle"
  );
  const modalRef = useRef<HTMLDivElement | null>(null);
  const submitButtonRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (open) {
      setStatus("idle");
      submitButtonRef.current?.focus();
    }
  }, [open]);

  const sanitizedSummary = useMemo(
    () => String(redactPII(errorSummary)),
    [errorSummary]
  );

  const handleClose = () => {
    setUserMessage("");
    setStatus("idle");
    onClose();
  };

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setStatus("submitting");

    const safeMessage = redactPII(userMessage);
    await onSubmit({
      userMessage:
        typeof safeMessage === "string" ? safeMessage : String(safeMessage),
    });

    setStatus("success");
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      handleClose();
    }

    if (event.key !== "Tab" || !modalRef.current) {
      return;
    }

    const focusableElements = Array.from(
      modalRef.current.querySelectorAll<HTMLElement>(
        "button, a[href], input, textarea, select, [tabindex]:not([tabindex='-1'])"
      )
    ).filter((element) => !element.hasAttribute("disabled"));

    if (focusableElements.length === 0) {
      return;
    }

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    if (event.shiftKey && document.activeElement === firstElement) {
      event.preventDefault();
      lastElement.focus();
    } else if (!event.shiftKey && document.activeElement === lastElement) {
      event.preventDefault();
      firstElement.focus();
    }
  };

  if (!open) {
    return null;
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="report-issue-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4 py-6"
      onKeyDown={handleKeyDown}
    >
      <div
        ref={modalRef}
        className="w-full max-w-2xl rounded-3xl bg-neutral-950 p-8 shadow-2xl shadow-black/50"
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2
              id="report-issue-title"
              className="text-2xl font-semibold text-white"
            >
              Report an issue
            </h2>
            <p className="mt-2 text-sm text-neutral-400">
              We will send a report with your request details and the error
              summary.
            </p>
          </div>
          <button
            type="button"
            onClick={handleClose}
            className="rounded-full bg-white/10 px-4 py-2 text-sm text-white transition hover:bg-white/20"
          >
            Close
          </button>
        </div>

        <div className="mt-6 space-y-4 rounded-3xl border border-white/10 bg-white/5 p-4">
          <p className="text-sm font-semibold text-neutral-200">
            Error summary
          </p>
          <p className="whitespace-pre-wrap rounded-2xl bg-neutral-900 p-4 text-sm text-neutral-200">
            {sanitizedSummary || "No summary available."}
          </p>

          <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
            <div>
              <label className="text-sm text-neutral-300">Request ID</label>
              <div className="mt-2 overflow-hidden rounded-2xl bg-neutral-900 px-3 py-2 text-sm text-neutral-200">
                {requestId || "Unavailable"}
              </div>
            </div>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <label className="block text-sm font-semibold text-neutral-200">
            Additional details
          </label>
          <textarea
            value={userMessage}
            onChange={(event) => setUserMessage(event.target.value)}
            rows={5}
            className="w-full rounded-3xl border border-white/10 bg-neutral-900 px-4 py-3 text-sm text-white outline-none transition focus:border-white/30"
            placeholder="What were you doing when this happened?"
          />
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-neutral-400">
              Your message will be sanitized before sending.
            </p>
            <button
              ref={submitButtonRef}
              type="submit"
              disabled={status === "submitting" || status === "success"}
              className="inline-flex items-center justify-center rounded-full bg-white px-6 py-3 text-sm font-semibold text-neutral-950 transition hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {status === "submitting" ? "Sending..." : "Send report"}
            </button>
          </div>
        </form>

        {status === "success" ? (
          <div className="mt-4 rounded-3xl bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
            Issue report submitted successfully.
          </div>
        ) : null}
      </div>
    </div>
  );
}

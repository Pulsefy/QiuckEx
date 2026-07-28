"use client";

export function LoadingState() {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex min-h-[60vh] flex-col items-center justify-center px-6 text-center"
    >
      <div className="relative" aria-hidden="true">
        <div className="w-16 h-16 border-4 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
      </div>
      <p className="mt-8 text-lg font-semibold text-foreground">
        Loading payment details...
      </p>
      <p className="mt-3 max-w-sm text-sm leading-6 text-subtle">
        Please wait while we fetch the payment information
      </p>
    </div>
  );
}

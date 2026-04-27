"use client";

export function LoadingState() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh]">
      <div className="relative">
        <div className="w-16 h-16 border-4 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin" />
      </div>
      <p className="mt-8 text-lg text-neutral-400">
        Loading payment details...
      </p>
      <p className="mt-2 text-sm text-neutral-600">
        Please wait while we fetch the payment information
      </p>
    </div>
  );
}

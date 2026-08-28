"use client";

import { Suspense } from "react";
import PaymentHistoryContent from "./PaymentHistoryContent";

export default function PaymentHistoryPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center min-h-screen">
          <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <PaymentHistoryContent />
    </Suspense>
  );
}

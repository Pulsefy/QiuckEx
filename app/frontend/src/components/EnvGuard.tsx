"use client";

import { validateEnv } from "@/lib/env";
import MisconfigurationPage from "@/app/misconfiguration/page";

export function EnvGuard({ children }: { children: React.ReactNode }) {
  const validation = validateEnv();

  if (!validation.isValid) {
    return <MisconfigurationPage />;
  }

  return <>{children}</>;
}

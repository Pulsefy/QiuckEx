"use client";

import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { usePathname } from "next/navigation";

export interface RequestContextValue {
  requestId: string;
  correlationId?: string;
}

const RequestContext = createContext<RequestContextValue | null>(null);

declare global {
  interface Window {
    __REQUEST_HEADERS__?: {
      requestId?: string;
      correlationId?: string;
    };
  }
}

function getRequestHeaders() {
  if (typeof window === "undefined") {
    return { requestId: undefined, correlationId: undefined };
  }

  return window.__REQUEST_HEADERS__ ?? {
    requestId: undefined,
    correlationId: undefined,
  };
}

export function RequestContextProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const initialHeaders = getRequestHeaders();
  const [requestId, setRequestId] = useState(
    initialHeaders.requestId ?? crypto.randomUUID()
  );
  const [correlationId, setCorrelationId] = useState(
    initialHeaders.correlationId
  );

  useEffect(() => {
    setRequestId(crypto.randomUUID());
    setCorrelationId(getRequestHeaders().correlationId);
  }, [pathname]);

  const value = useMemo(
    () => ({ requestId, correlationId }),
    [requestId, correlationId]
  );

  return (
    <RequestContext.Provider value={value}>
      {children}
    </RequestContext.Provider>
  );
}

export function useRequestContext(): RequestContextValue {
  const context = useContext(RequestContext);
  if (!context) {
    throw new Error("useRequestContext must be used within RequestContextProvider");
  }
  return context;
}

export { RequestContext };

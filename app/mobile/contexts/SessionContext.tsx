import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { fetchSessionBootstrap, type BootstrapResponse } from '../services/session-bootstrap';
import { useEnvironment } from './EnvironmentContext';

export interface SessionContextValue {
  isReady: boolean;
  isFetching: boolean;
  error: Error | null;
  data: BootstrapResponse | null;
  fetchSession: () => Promise<void>;
}

const SessionContext = createContext<SessionContextValue | undefined>(undefined);

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const { current, processMetadata } = useEnvironment();
  const [isReady, setIsReady] = useState(false);
  const [isFetching, setIsFetching] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [data, setData] = useState<BootstrapResponse | null>(null);

  const fetchSession = useCallback(async () => {
    setIsFetching(true);
    setError(null);
    try {
      const response = await fetchSessionBootstrap(current.apiUrl);
      setData(response);
      processMetadata(response.metadata);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to fetch session'));
    } finally {
      setIsFetching(false);
      setIsReady(true);
    }
  }, [current.apiUrl, processMetadata]);

  useEffect(() => {
    void fetchSession();
  }, [fetchSession]);

  const value = useMemo(
    () => ({ isReady, isFetching, error, data, fetchSession }),
    [isReady, isFetching, error, data, fetchSession]
  );

  return (
    <SessionContext.Provider value={value}>
      {children}
    </SessionContext.Provider>
  );
}

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) {
    throw new Error('useSession must be used within a <SessionProvider>');
  }
  return ctx;
}

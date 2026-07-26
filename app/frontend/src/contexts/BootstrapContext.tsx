import React, { createContext, useContext, useEffect, useState } from 'react';
import { BootstrapConfig, FALLBACK_BOOTSTRAP_CONFIG } from '../config/bootstrap.config';
import { fetchBootstrapConfig } from '../services/bootstrap.service';

interface BootstrapContextType {
  config: BootstrapConfig;
  isLoading: boolean;
  error: Error | null;
}

const BootstrapContext = createContext<BootstrapContextType>({
  config: FALLBACK_BOOTSTRAP_CONFIG,
  isLoading: true,
  error: null,
});

export const BootstrapProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [config, setConfig] = useState<BootstrapConfig>(FALLBACK_BOOTSTRAP_CONFIG);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    let isMounted = true;

    const initBootstrap = async () => {
      try {
        const loadedConfig = await fetchBootstrapConfig();
        if (isMounted) {
          setConfig(loadedConfig);
        }
      } catch (err) {
        if (isMounted) {
          setError(err instanceof Error ? err : new Error('Unknown bootstrap error'));
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    };

    initBootstrap();

    return () => {
      isMounted = false;
    };
  }, []);

  if (isLoading) {
    return <div className="flex h-screen w-screen items-center justify-center">Loading Environment...</div>;
  }

  return (
    <BootstrapContext.Provider value={{ config, isLoading, error }}>
      {children}
    </BootstrapContext.Provider>
  );
};

export const useBootstrap = () => useContext(BootstrapContext);
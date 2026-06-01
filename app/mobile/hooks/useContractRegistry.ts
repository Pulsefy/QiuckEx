import { useState, useEffect } from 'react';
import { ContractRegistryService, ContractRegistry } from '../services/contract-registry';

export function useContractRegistry(requiredContracts: string[], backendUrl: string) {
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    ContractRegistryService.sync(backendUrl)
      .then(registry => {
        const missing = requiredContracts.filter(c => !registry[c]);
        if (missing.length > 0) {
          throw new Error(`Incompatible registry: missing ${missing.join(', ')}`);
        }
        setIsReady(true);
      })
      .catch(err => setError(err.message));
  }, [backendUrl]);

  return { isReady, error };
}
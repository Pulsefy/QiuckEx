import { BootstrapConfig, FALLBACK_BOOTSTRAP_CONFIG } from '../config/bootstrap.config';

export const fetchBootstrapConfig = async (): Promise<BootstrapConfig> => {
  const baseUrl = process.env.VITE_API_BASE_URL || '';
  
  try {
    const response = await fetch(`${baseUrl}/v1/network/bootstrap`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      signal: AbortSignal.timeout(5000) 
    });

    if (!response.ok) {
      throw new Error(`Bootstrap fetch failed with status: ${response.status}`);
    }

    const data: Partial<BootstrapConfig> = await response.json();

    return {
      network: { ...FALLBACK_BOOTSTRAP_CONFIG.network, ...data.network },
      contracts: { ...FALLBACK_BOOTSTRAP_CONFIG.contracts, ...data.contracts },
      backendMetadata: { ...FALLBACK_BOOTSTRAP_CONFIG.backendMetadata, ...data.backendMetadata },
    };
  } catch (error) {
    console.warn('Failed to load backend bootstrap. Using fallback configuration.', error);
    return FALLBACK_BOOTSTRAP_CONFIG;
  }
};
"use client";

import { useBootstrap } from "../contexts/BootstrapContext";

export function EnvironmentBanner() {
  const { config, isLoading } = useBootstrap();

  if (isLoading) return null;

  const isProduction =
    config.backendMetadata.environmentName === "production" ||
    config.network.environment === "mainnet";

  if (isProduction) return null;

  const isPreview = config.backendMetadata.environmentName === "preview" || !!config.backendMetadata.branchName;
  const envName = config.backendMetadata.environmentName || config.network.environment;
  
  return (
    <div data-testid="environment-banner" className="w-full bg-amber-500 text-black text-center py-2 text-sm font-medium">
      ⚠️ This is the {envName.toUpperCase()} environment for testing purposes only. Do not use real funds.
      {config.backendMetadata.branchName && (
        <span className="ml-2 px-2 py-0.5 bg-amber-600 rounded text-white text-xs">
          Branch: {config.backendMetadata.branchName}
        </span>
      )}
    </div>
  );
}

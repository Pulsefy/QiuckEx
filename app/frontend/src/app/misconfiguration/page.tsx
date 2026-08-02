"use client";

import { validateEnv } from "@/lib/env";

export default function MisconfigurationPage() {
  const validation = validateEnv();

  return (
    <div className="min-h-screen bg-background text-foreground flex items-center justify-center p-6">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <div className="w-16 h-16 bg-red-100 text-red-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg
              className="w-8 h-8"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
              />
            </svg>
          </div>
          <h1 className="text-3xl font-bold tracking-tight">
            Configuration Error
          </h1>
          <p className="mt-2 text-muted">
            The application is missing required configuration.
          </p>
        </div>

        <div className="bg-red-50 border border-red-200 rounded-lg p-6 space-y-4">
          {validation.missing.length > 0 && (
            <div>
              <h3 className="font-semibold text-red-800 mb-2">
                Missing Required Variables:
              </h3>
              <ul className="list-disc list-inside space-y-1 text-red-700">
                {validation.missing.map((key) => (
                  <li key={key} className="font-mono text-sm">
                    {key}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {validation.invalid.length > 0 && (
            <div>
              <h3 className="font-semibold text-red-800 mb-2">
                Invalid Variables:
              </h3>
              <ul className="list-disc list-inside space-y-1 text-red-700">
                {validation.invalid.map(({ key, reason }) => (
                  <li key={key} className="text-sm">
                    <span className="font-mono">{key}</span>: {reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <div className="text-center text-sm text-muted">
          <p>
            Please contact your system administrator or check the deployment
            configuration.
          </p>
        </div>
      </div>
    </div>
  );
}

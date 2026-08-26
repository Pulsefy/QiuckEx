import type { NextConfig } from "next";
import path from "path";

const CSP_HEADER_VALUE = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://horizon-testnet.stellar.org",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https:",
  "font-src 'self' data:",
  "connect-src 'self' https: wss:",
  "frame-ancestors 'none'",
].join("; ");

const nextConfig: NextConfig = {
  // Transpile the local workspace package so webpack resolves its deps
  // (e.g. openapi-fetch) from the frontend's own node_modules rather than
  // relying on hoisting that is absent in the flat `npm ci` CI install.
  transpilePackages: ["@quickex/api-client"],

  // Point Next.js at the monorepo root so it can trace shared packages
  // (e.g. packages/api-client) correctly and suppress the lockfile warning.
  outputFileTracingRoot: path.join(__dirname, "../../"),

  // Enforce HTTPS and Content-Security-Policy in production
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "Content-Security-Policy",
            value: CSP_HEADER_VALUE,
          },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains; preload",
          },
          {
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            key: "X-XSS-Protection",
            value: "1; mode=block",
          },
          {
            key: "Referrer-Policy",
            value: "strict-origin-when-cross-origin",
          },
        ],
      },
      {
        source: "/.well-known/apple-app-site-association",
        headers: [
          { key: "Content-Type", value: "application/json; charset=utf-8" },
          { key: "Cache-Control", value: "public, max-age=300" },
        ],
      },
      {
        source: "/.well-known/assetlinks.json",
        headers: [
          { key: "Content-Type", value: "application/json; charset=utf-8" },
          { key: "Cache-Control", value: "public, max-age=300" },
        ],
      },
      {
        source: "/api/og",
        headers: [
          { key: "Cache-Control", value: "public, max-age=60, stale-while-revalidate=300" },
          { key: "Access-Control-Allow-Origin", value: "*" },
        ],
      },
    ];
  },

  env: {
    NEXT_PUBLIC_QUICKEX_API_URL: process.env.NEXT_PUBLIC_QUICKEX_API_URL,
    NEXT_PUBLIC_SITE_URL: process.env.NEXT_PUBLIC_SITE_URL,
    NEXT_PUBLIC_STELLAR_NETWORK: process.env.NEXT_PUBLIC_STELLAR_NETWORK,
    NEXT_PUBLIC_VERCEL_ENV: process.env.NEXT_PUBLIC_VERCEL_ENV,
    NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF: process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF,
    NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA: process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA,
    NEXT_PUBLIC_VERCEL_URL: process.env.NEXT_PUBLIC_VERCEL_URL,
    NEXT_PUBLIC_VERCEL_DEPLOYED_AT: process.env.NEXT_PUBLIC_VERCEL_DEPLOYED_AT,
    NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION: process.env.NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION,
    NEXT_PUBLIC_APP_VERSION: process.env.NEXT_PUBLIC_APP_VERSION,
  },

  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "**",
      },
    ],
  },

  experimental: {
    optimizePackageImports: ["lucide-react"],
  },

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  webpack(config: any) {
    // When transpilePackages compiles @quickex/api-client source files,
    // webpack resolves imports (e.g. 'openapi-fetch') relative to the package
    // directory. In CI the api-client package has no node_modules of its own,
    // so we pin the resolution to the frontend's node_modules explicitly.
    config.resolve ??= {};
    config.resolve.alias = {
      ...config.resolve.alias,
      "openapi-fetch": path.resolve(__dirname, "node_modules/openapi-fetch"),
    };
    return config;
  },
};

export default nextConfig;

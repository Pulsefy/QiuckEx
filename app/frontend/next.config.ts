import type { NextConfig } from "next";

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
};

export default nextConfig;

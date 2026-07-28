import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Enforce HTTPS in production to prevent mixed-content issues
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
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
        // Allow social crawlers to fetch OG images
        source: "/api/og",
        headers: [
          { key: "Cache-Control", value: "public, max-age=60, stale-while-revalidate=300" },
          { key: "Access-Control-Allow-Origin", value: "*" },
        ],
      },
    ];
  },

  // Environment-specific configuration
  env: {
    // Ensure all API URLs use HTTPS in production
    NEXT_PUBLIC_QUICKEX_API_URL: process.env.NEXT_PUBLIC_QUICKEX_API_URL,
    NEXT_PUBLIC_SITE_URL: process.env.NEXT_PUBLIC_SITE_URL,
    NEXT_PUBLIC_STELLAR_NETWORK: process.env.NEXT_PUBLIC_STELLAR_NETWORK,
    // Vercel system env vars (already NEXT_PUBLIC_ prefixed so Vercel exposes
    // them to the browser automatically, but listing them here ensures they
    // are available for local overrides via .env.local as well)
    NEXT_PUBLIC_VERCEL_ENV: process.env.NEXT_PUBLIC_VERCEL_ENV,
    NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF: process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF,
    NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA: process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA,
    NEXT_PUBLIC_VERCEL_URL: process.env.NEXT_PUBLIC_VERCEL_URL,
    // Set by the GitHub Actions deploy workflow: date -u +%FT%TZ
    NEXT_PUBLIC_VERCEL_DEPLOYED_AT: process.env.NEXT_PUBLIC_VERCEL_DEPLOYED_AT,
    // Set by app/contract CI deploy step
    NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION: process.env.NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION,
    // App version
    NEXT_PUBLIC_APP_VERSION: process.env.NEXT_PUBLIC_APP_VERSION,
  },

  // Image optimization with allowed domains
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "**",
      },
    ],
  },

  // Enable experimental features for better performance
  experimental: {
    optimizePackageImports: ["lucide-react"],
  },
};

export default nextConfig;

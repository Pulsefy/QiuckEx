# Runtime Config Matrix

How every client resolves API URLs, Stellar network settings, contract IDs, and environment overrides — with drift, risks, and migration paths.

---

## 1. Key Runtime Config Fields

| Field | Backend | Frontend (Web) | Mobile |
|---|---|---|---|
| **API base URL** | N/A (serves) | `NEXT_PUBLIC_QUICKEX_API_URL` | `extra.apiUrl` → `EXPO_PUBLIC_API_URL` |
| **Stellar network** | `NETWORK` / `STELLAR_NETWORK` | `NEXT_PUBLIC_STELLAR_NETWORK` | `extra.stellarNetwork` / `STELLAR_NETWORK` env |
| **Horizon URL** | `HORIZON_URL` (override) → network default | runtime via backend `GET /v1/network` | runtime via `GET /v1/network` |
| **Soroban RPC URL** | `SOROBAN_RPC_URL` + `SOROBAN_RPC_URLS` (failover) | runtime via backend | runtime via backend |
| **Contract ID** | `QUICKEX_CONTRACT_ID` env var | runtime via `GET /contracts/registry` | runtime via `GET /contracts/registry` (⚠️ broken path) |
| **Explorer URL** | `STELLAR_EXPLORER_URL` (override) → network default | via backend | via backend |
| **App version** | `SENTRY_RELEASE` | `NEXT_PUBLIC_APP_VERSION` | `expo.version` / `extra.appVersion` |
| **Environment name** | `ENVIRONMENT_NAME` / `NODE_ENV` | `NEXT_PUBLIC_VERCEL_ENV` | `extra.environment` (`APP_ENV`) |
| **CORS origins** | `CORS_ALLOWED_ORIGINS` + `CORS_VERCEL_PROJECT` | N/A (browser enforced) | N/A |
| **Rate limits** | Env vars + hardcoded testnet defaults | N/A | N/A |
| **Build tag** | N/A | `NEXT_PUBLIC_VERCEL_GIT_COMMIT_REF` | `extra.buildTag` |
| **Contract registry version** | N/A (serves) | `NEXT_PUBLIC_CONTRACT_REGISTRY_VERSION` | from registry endpoint |

---

## 2. Source of Truth per Client

### Backend (`app/backend`)

```
process.env
  │
  ├── Joi validation (env.schema.ts) ────── defaults, types, required checks
  │
  ├── AppConfigService (app-config.service.ts) ─── typed getter accessors
  │
  ├── resolveNetworkSnapshot() (network.config.ts)
  │       ├── reads NETWORK | STELLAR_NETWORK  →  "testnet" | "mainnet"
  │       ├── reads HORIZON_URL / SOROBAN_RPC_URL / STELLAR_EXPLORER_URL
  │       ├── falls back to DEFAULT_ENDPOINTS[network] hardcoded map
  │       └── validates all URLs are http/https
  │
  ├── stellar.config.ts (registerAs('stellar'))
  │       └── builds full snapshot: passphrase, horizon, soroban, explorer URLs
  │
  ├── throttlerConfig (rate-limit.config.ts)
  │       └── env vars with hardcoded testnet-specific limits (✗)
  │
  └── GET /v1/network ───── exposed to clients
```

### Frontend (`app/frontend`)

```
process.env (server) / NEXT_PUBLIC_* (browser)
  │
  ├── next.config.ts ─── env passthrough (all NEXT_PUBLIC_* vars)
  │
  ├── src/lib/env.ts ─── validation:
  │       ├── requires NEXT_PUBLIC_QUICKEX_API_URL (valid URL)
  │       └── requires NEXT_PUBLIC_STELLAR_NETWORK ("testnet" | "mainnet")
  │
  ├── src/lib/api.ts ─── getQuickexApiBase():
  │       └── NEXT_PUBLIC_QUICKEX_API_URL ?? "http://localhost:4000"
  │
  ├── src/lib/deployment-info.ts ─── Vercel git/env metadata
  │       └── apiUrl fallback: "http://localhost:4000"
  │
  ├── src/lib/og-metadata.ts (SSR only):
  │       └── QUICKEX_INTERNAL_API_URL ?? NEXT_PUBLIC_QUICKEX_API_URL ?? "http://localhost:4000"
  │
  └── vercel.json ─── hardcoded production defaults (✗ risky for preview)
```

### Mobile (`app/mobile`)

```
Build-time:
  APP_ENV ─── app.config.ts ─── extra.* ─── Constants.expoConfig.extra
     │                                │
     │  process.env.CI? 'production' : 'dev'   (default)
     │  EAS profiles override: dev / staging / production
     │
     ├── apiUrl(env):  "https://api.quickex.to"        (production)
     │                  "https://staging-api.quickex.to"  (staging)
     │                  EXPO_PUBLIC_API_URL ?? "http://localhost:3000"  (dev)
     │
     ├── stellarNetwork: "mainnet" (production) / "testnet" (else)
     ├── bundleIdentifier / androidPackage per env
     └── buildTag, buildNumber

Runtime:
  src/config/environment.ts ─── hardcoded ENVIRONMENTS map (✗)
  src/config/build.ts ─── reads from Constants.expoConfig.extra with fallback:
      ├── API_URL: extra.apiUrl ?? EXPO_PUBLIC_API_URL ?? "http://localhost:3000"
      ├── STELLAR_NETWORK: extra.stellarNetwork ?? "mainnet"
      └── APP_ENVIRONMENT: extra.environment ?? "production"

  Services (transactions.ts, link-metadata.ts, in-app-notifications.ts):
      Constants.expoConfig.extra.apiUrl ?? EXPO_PUBLIC_API_URL ?? "http://localhost:3000"

  EnvironmentContext ─── loads persisted environment ID → ENVIRONMENTS map
  SessionContext ─── fetchSessionBootstrap(current.apiUrl)
```

---

## 3. Environment Differences

### API Base URL

| Environment | Backend | Frontend | Mobile |
|---|---|---|---|
| **Local dev** | `http://localhost:4000` | `http://localhost:4000` | `http://localhost:3000` **✗** |
| **Preview (PR branch)** | `https://preview-api.quickex.to` | `https://preview-api.quickex.to` | `https://preview-api.quickex.to` |
| **Staging** | `https://staging-api.quickex.to` | `https://staging-api.quickex.to` | `https://staging-api.quickex.to` |
| **Shared testnet** | `https://testnet-api.quickex.to` | `https://testnet-api.quickex.to` | `https://testnet-api.quickex.to` |
| **Production** | `https://api.quickex.to` | `https://api.quickex.to` | `https://api.quickex.to` |

### Stellar Network

| Environment | Backend | Frontend | Mobile |
|---|---|---|---|
| **Local dev** | `testnet` | `testnet` (default in `deployment-info.ts`) | `testnet` |
| **Preview** | `testnet` | `testnet` | `testnet` |
| **Staging** | `testnet` | `testnet` | `testnet` |
| **Shared testnet** | `testnet` | `testnet` | `testnet` |
| **Production** | `mainnet` | `mainnet` | `mainnet` |

### Contract ID Resolution

| Environment | Backend | Frontend | Mobile |
|---|---|---|---|
| **All** | `QUICKEX_CONTRACT_ID` env var → ingestion service | `GET /contracts/registry` (HTTP) | `GET /contracts/registry` (HTTP) — **broken** |
| **Local** | set in `.env` | via backend | via backend (EXPO_PUBLIC_API_URL must point to localhost:4000) |

### Key Config Fields per Environment

| Field | Local | Preview | Staging | Testnet | Production |
|---|---|---|---|---|---|
| `NETWORK` | testnet | testnet | testnet | testnet | mainnet |
| `NODE_ENV` | development | production | production | production | production |
| `ENVIRONMENT_NAME` | development | — | staging | — | production |
| `CORS` | localhost | Vercel preview pattern | quickex.to + staging subdomain | quickex.to | quickex.to |
| `ENV_PARITY_CHECK` | off | off | optional | off | off |
| `SHADOW_TRAFFIC` | off | off | optional | off | off |
| Rate limits | defaults | defaults | defaults | elevated (hardcoded) | defaults |
| Supabase | local (127.0.0.1:54321) | production | production | production | production |

---

## 4. Deprecated / Risky Hardcoded Assumptions

### 🔴 Must Fix — Breaks in Production

| # | Issue | Location | Impact | Fix |
|---|---|---|---|---|
| 1 | **Mobile services default to `localhost:3000`** (frontend port, not `:4000`) | `build.ts:14`, `transactions.ts:12`, `link-metadata.ts:11`, `in-app-notifications.ts:10`, `link-generator.tsx:26`, `app.config.ts:50` | Local mobile dev silently fails against local backend | Change all fallbacks to `http://localhost:4000` |
| 2 | **`payment-confirmation.tsx` falls back to `api.quickex.com`** (`.com` vs `.to`) | `payment-confirmation.tsx:29` | Production mobile builds would hit a non-existent domain | Change to `https://api.quickex.to` or remove fallback |
| 3 | **Mobile contract registry calls `/api/contracts/registry`** (wrong prefix) | `contract-registry.ts:25` | Escrow registry sync 404s on payment-confirmation screen | Drop the `/api` prefix |
| 4 | **`vercel.json` hardcodes production URLs for all deployments** | `vercel.json:7-28` | Preview deployments get production API URLs unless dashboard-overridden | Remove `env` from `vercel.json`; set in Vercel dashboard per-environment |

### 🟡 Should Fix — Config Drift Risk

| # | Issue | Location | Impact | Fix |
|---|---|---|---|---|
| 5 | **Mobile `ENVIRONMENTS` hardcoded in source** | `environment.ts:11-39` | Changing API URLs requires app store update, no runtime control | Drive from `app.config.ts` `extra` or remote config |
| 6 | **Backend fallback defaults use `quickex.io`** (wrong TLD) | `env.schema.ts:144,148` | Unknown branches resolve to non-existent endpoints | Change to `quickex.to` |
| 7 | **Rate limit config hardcodes testnet-specific limits** | `rate-limit.config.ts:53-57` | Environment logic is imperative (reads `process.env.NETWORK` at import time) | Make limits fully env-var-driven |
| 8 | **Three TLDs in active use (`.to`, `.com`, `.io`)** | Multiple files | Confusion, config drift, silent failover to wrong domains | Consolidate to `.to` everywhere |
| 9 | **Mobile `app.config.ts` dev fallback uses `localhost:3000`** | `app.config.ts:50` | Same port drift as #1 — local mobile never reaches backend out of the box | Change to `http://localhost:4000` |
| 10 | **Mobile `defaultEnvironment` in CI is `'production'`** | `app.config.ts:3` | CI test builds default to production API (mainnet) unless `APP_ENV` is explicitly set | Default to `'testnet'` or make configurable |

### 🟢 Informational — Monitor

| # | Issue | Location | Notes |
|---|---|---|---|
| 11 | **Frontend `deployment-info.ts` falls back to `"http://localhost:4000"`** | `deployment-info.ts:60` | Intentional; local dev fallback. Safe as long as `NEXT_PUBLIC_QUICKEX_API_URL` is set in CI/CD |
| 12 | **Mobile `EnvironmentSwitcher` allows runtime environment switching** | `EnvironmentSwitcher.tsx` | Useful for testers, but could ship to prod. Already gated: diagnostics hidden when `vercelEnv=production && network=mainnet` |
| 13 | **Backend has no global route prefix** | `main.ts` (no `setGlobalPrefix`) | `v1/receipts` and `api/environment-parity` are the only prefixed routes — historical accident, not convention |
| 14 | **`GET /session/bootstrap` and `POST /feedback` have no backend routes** | mobile services exist, backend missing | Mobile clients tolerate failures gracefully, but features are non-functional |

---

## 5. Deployment Profiles Summary

### Backend

| Profile | How triggered | Key env vars |
|---|---|---|
| Local | `.env` file | `NETWORK=testnet`, `NODE_ENV=development`, `SUPABASE_URL=http://127.0.0.1:54321` |
| Preview | Branch deploy + CORS allowlist | `NETWORK=testnet`, `NODE_ENV=production` |
| Staging | Staging deploy | `NETWORK=testnet`, `NODE_ENV=production`, `ENVIRONMENT_NAME=staging` |
| Production | Main branch deploy | `NETWORK=mainnet`, `NODE_ENV=production`, restricted CORS |

### Frontend (Vercel)

| Profile | How triggered | Key overrides |
|---|---|---|
| Local | `.env.local` | `NEXT_PUBLIC_QUICKEX_API_URL=http://localhost:4000`, `NEXT_PUBLIC_STELLAR_NETWORK=testnet` |
| Preview | PR branch → Vercel | Must set `NEXT_PUBLIC_QUICKEX_API_URL=https://preview-api.quickex.to` in Vercel dashboard |
| Staging | `staging` branch → Vercel | `NEXT_PUBLIC_STELLAR_NETWORK=testnet` |
| Production | `main` branch → Vercel | `NEXT_PUBLIC_QUICKEX_API_URL=https://api.quickex.to`, `STELLAR_NETWORK=mainnet` |

### Mobile (EAS Build)

| Profile | EAS profile | `APP_ENV` | `STELLAR_NETWORK` | API URL |
|---|---|---|---|---|
| Dev | `eas build --profile dev` | `dev` | `testnet` | `EXPO_PUBLIC_API_URL ?? http://localhost:3000` |
| Staging | `eas build --profile staging` | `staging` | `testnet` | `https://staging-api.quickex.to` |
| Production | `eas build --profile production` | `production` | `mainnet` | `https://api.quickex.to` |

---

## 6. How to Trace Config at Runtime

```bash
# Backend - verify resolved network
curl http://localhost:4000/v1/network
# → { network: "testnet", passphrase: "Test SDF Network ; September 2015",
#     horizonUrl: "https://horizon-testnet.stellar.org", ... }

# Frontend - check deployment info (open browser console)
# From getDeploymentInfo():
# { apiUrl, network, vercelEnv, branch, commitSha, ... }
window.__NEXT_DATA__.props.pageProps.deploymentInfo

# Mobile - EnvironmentSwitcher UI shows current environment
# Or check persisted value:
AsyncStorage.getItem('@selected_environment')
# → "production" | "staging" | "testnet" | "branch-preview"
```

---

## 7. Migration Roadmap

| Priority | Action | Tracks |
|---|---|---|
| P0 | Fix mobile fallback `localhost:3000` → `localhost:4000` (6 service files + `app.config.ts`) | #1, #9 |
| P0 | Fix `payment-confirmation.tsx` `.com` → `.to` | #2 |
| P0 | Fix mobile contract registry path | #3 |
| P0 | Remove hardcoded env from `vercel.json`; use Vercel dashboard per-environment | #4 |
| P1 | Drive mobile environments from build-time `extra` not source-code map | #5 |
| P1 | Fix backend `FALLBACK_API_URL` / `FALLBACK_FRONTEND_URL` TLD | #6 |
| P1 | Move rate-limit testnet overrides to env vars | #7 |
| P2 | Consolidate all URLs to `quickex.to` TLD | #8 |
| P2 | Implement backend `GET /session/bootstrap` and `POST /feedback` | #14 |

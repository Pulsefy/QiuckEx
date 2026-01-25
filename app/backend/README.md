# QuickEx Backend (NestJS)

## Setup

1. Install deps from repo root:

```bash
pnpm install
```

2. Provide environment variables (optional for now):

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `STELLAR_NETWORK` (optional, defaults to `testnet`)

If these are missing, the backend will still start but will log a warning and Supabase will remain disabled.

## Stellar configuration

### Network

- Env var: `STELLAR_NETWORK`
- Allowed values: `testnet`, `mainnet`
- Default: `testnet`
- Invalid values fail fast with a startup error.

Example `.env`:

```bash
STELLAR_NETWORK=testnet
```

### Supported assets

Asset validation is driven by `SUPPORTED_ASSETS` in `src/config/stellar.config.ts`.

Native asset shape:

```ts
{ type: 'native', code: 'XLM' }
```

Issued asset shape:

```ts
{ type: 'credit_alphanum4', code: 'USDC', issuer: 'G...ISSUER' }
```

How to add a new supported asset:

1. Add a new entry to `SUPPORTED_ASSETS`.
2. For issued assets, include the exact issuer (case-sensitive).
3. Update tests and docs.

Example issued asset:

```ts
{
  type: 'credit_alphanum4',
  code: 'EURT',
  issuer: 'GEXAMPLEISSUERADDRESS'
}
```

## Scripts

Run from repo root:

```bash
pnpm turbo run dev --filter=@quickex/backend
pnpm turbo run test --filter=@quickex/backend
pnpm turbo run type-check --filter=@quickex/backend
pnpm turbo run lint --filter=@quickex/backend
pnpm turbo run build --filter=@quickex/backend
```

## Endpoints

- `GET /health` -> `{ "status": "ok" }`
- `POST /username` -> validates body and returns `{ "ok": true }` (stub; no DB writes)

## Local run

```bash
pnpm turbo run dev --filter=@quickex/backend
```

Default port: `4000` (override with `PORT`).

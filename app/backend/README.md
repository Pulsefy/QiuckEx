# QuickEx Backend (NestJS)

## Setup

1. Install deps from repo root:

```bash
pnpm install
```

2. Provide environment variables (optional for now):

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`

If these are missing, the backend will still start but will log a warning and Supabase will remain disabled.

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

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

## API Versioning

All endpoints are versioned using URI versioning. The default version is `v1`.

**Versioned Routes:**
- `GET /v1/health` -> `{ "status": "ok" }`
- `POST /v1/username` -> validates body and returns `{ "ok": true }` (stub; no DB writes)

**Example:**
```bash
curl http://localhost:4000/v1/health
# Response: { "status": "ok" }
```

## Request Validation

The backend uses a global `ValidationPipe` with strict validation:
- **Whitelist**: Only properties defined in DTOs are allowed
- **Forbid Non-Whitelisted**: Extra properties in requests are rejected
- **Transform**: Request bodies are automatically transformed to DTO instances

**Example - Valid Request:**
```bash
curl -X POST http://localhost:4000/v1/username \
  -H "Content-Type: application/json" \
  -d '{"username": "alice123"}'
# Response: { "ok": true }
```

**Example - Invalid Request (extra field):**
```bash
curl -X POST http://localhost:4000/v1/username \
  -H "Content-Type: application/json" \
  -d '{"username": "alice123", "extra": "field"}'
# Response: 400 Bad Request
# {
#   "statusCode": 400,
#   "message": ["property extra should not exist"],
#   "error": "Bad Request"
# }
```

**Example - Invalid Request (wrong type):**
```bash
curl -X POST http://localhost:4000/v1/username \
  -H "Content-Type: application/json" \
  -d '{"username": 123}'
# Response: 400 Bad Request
# {
#   "statusCode": 400,
#   "message": ["username must be a string"],
#   "error": "Bad Request"
# }
```

## CORS Configuration

CORS is configured to allow requests from:
- `http://localhost:3000` (local frontend development)
- `https://app.quickex.example.com` (placeholder for production domain)

**Note:** For production, update the `allowedOrigins` array in `src/main.ts` with the actual production domain.

## Local run

```bash
pnpm turbo run dev --filter=@quickex/backend
```

Default port: `4000` (override with `PORT`).

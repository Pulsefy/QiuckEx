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

Run from repo root using TurboRepo filters:

- **Development**:
  ```bash
  pnpm turbo run dev --filter=@quickex/backend
  ```
- **Build**:
  ```bash
  pnpm turbo run build --filter=@quickex/backend
  ```
- **Test**:
  ```bash
  pnpm turbo run test --filter=@quickex/backend
  ```
- **Lint**:
  ```bash
  pnpm turbo run lint --filter=@quickex/backend
  ```
- **Type Check**:
  ```bash
  pnpm turbo run type-check --filter=@quickex/backend
  ```

## Endpoints

### Health Check
- **GET** `/health`
- **Response**:
  ```json
  { "status": "ok" }
  ```

### Usernames
- **POST** `/username`
- **Description**: Validates format and checks availability (stub).
- **Body**:
  ```json
  {
    "username": "example_user"
  }
  ```
- **Validation Rules**:
  - `IsString`, `IsNotEmpty`
  - Length: 3–32 characters
  - Pattern: `^[a-z0-9_]+$` (lowercase alphanumeric and underscores only)
- **Response**:
  ```json
  { "ok": true }
  ```

## Local run

To run the backend locally:

```bash
pnpm turbo run dev --filter=@quickex/backend
```

Default port: `4000` (override with `PORT`).

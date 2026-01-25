# QuickEx Backend (NestJS)

A NestJS-based backend API for the QuickEx Stellar exchange platform.

## Setup

### 1. Install dependencies

From the repository root:

```bash
pnpm install
```

### 2. Configure environment variables

Copy the example environment file and fill in the required values:

```bash
cp .env.example .env
```

**Required environment variables must be configured before the server will start.**

### Environment Variables

| Variable           | Required | Default       | Description                                           |
| ------------------ | -------- | ------------- | ----------------------------------------------------- |
| `PORT`             | No       | `4000`        | Port number for the HTTP server                       |
| `NODE_ENV`         | No       | `development` | Environment: `development`, `production`, or `test`   |
| `NETWORK`          | **Yes**  | -             | Stellar network: `testnet` or `mainnet`               |
| `SUPABASE_URL`     | **Yes**  | -             | Supabase project URL (e.g., `https://xxx.supabase.co`)|
| `SUPABASE_ANON_KEY`| **Yes**  | -             | Supabase anonymous (public) API key                   |

#### Getting Supabase credentials

1. Go to your [Supabase Dashboard](https://supabase.com/dashboard)
2. Select your project (or create a new one)
3. Navigate to **Project Settings** > **API**
4. Copy the **Project URL** → `SUPABASE_URL`
5. Copy the **anon/public** key → `SUPABASE_ANON_KEY`

#### Example `.env` file

```env
PORT=4000
NODE_ENV=development
NETWORK=testnet
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Environment Validation

The backend validates all environment variables at startup using a Joi schema. If required variables are missing or invalid, the application will:

1. Log a clear, actionable error message listing all missing/invalid keys
2. Exit with a non-zero exit code

**Note:** For security, actual secret values are never logged—only the key names.

## Scripts

Run from repo root using TurboRepo filters:

```bash
pnpm turbo run dev --filter=@quickex/backend      # Start development server
pnpm turbo run test --filter=@quickex/backend     # Run tests
pnpm turbo run type-check --filter=@quickex/backend  # TypeScript type checking
pnpm turbo run lint --filter=@quickex/backend     # Lint code
pnpm turbo run build --filter=@quickex/backend    # Build for production
```

## API Documentation (Swagger/OpenAPI)

Interactive API documentation is available via Swagger UI:

**URL:** `http://localhost:4000/docs`

The Swagger UI provides:
- Interactive endpoint exploration
- Request/response schema documentation
- "Try it out" functionality for testing endpoints
- Downloadable OpenAPI specification

### Screenshots

When the server is running, navigate to `/docs` to see:
- All available endpoints organized by tags
- Request body schemas with validation rules
- Response schemas and status codes
- Example payloads

## Endpoints

### Health

| Method | Path      | Description         | Response                  |
| ------ | --------- | ------------------- | ------------------------- |
| GET    | `/health` | Health check        | `{ "status": "ok" }`      |

### Usernames

| Method | Path        | Description           | Request Body                      | Response              |
| ------ | ----------- | --------------------- | --------------------------------- | --------------------- |
| POST   | `/username` | Create a new username | `{ "username": "alice_123" }`     | `{ "ok": true }`      |

**Username validation rules:**
- 3-32 characters
- Lowercase letters, numbers, and underscores only
- Pattern: `^[a-z0-9_]+$`

## Local Development

### Start the development server

To run the backend locally:

```bash
pnpm turbo run dev --filter=@quickex/backend
```

The server will start on the configured port (default: `4000`).

### Verify the server is running

```bash
curl http://localhost:4000/health
# Response: {"status":"ok"}
```

### View API documentation

Open `http://localhost:4000/docs` in your browser.

## Architecture

```
src/
├── main.ts                 # Application entry point, Swagger setup
├── app.module.ts           # Root module
├── config/                 # Configuration module
│   ├── env.schema.ts       # Joi validation schema
│   ├── app-config.service.ts # Typed config accessors
│   └── config.module.ts    # Config module setup
├── health/                 # Health check module
│   ├── health.controller.ts
│   └── health-response.dto.ts
├── usernames/              # Username management module
│   ├── usernames.controller.ts
│   ├── create-username.dto.ts
│   └── create-username-response.dto.ts
└── supabase/               # Supabase integration
    ├── supabase.service.ts
    └── supabase.module.ts
```

## Testing

```bash
pnpm turbo run test --filter=@quickex/backend
```

Tests include:
- Environment schema validation tests (`env.schema.spec.ts`)
- Integration tests for endpoints (`app.spec.ts`)

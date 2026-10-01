# Development Setup

## Environment

Copy the provided environment template.

```bash
cp .env.example .env
```

Fill in all required credentials before starting the application.

---

## Backend

Install dependencies.

```bash
npm install
```

Run migrations.

```bash
npm run migration:run
```

or

```bash
npx prisma migrate dev
```

Start development.

```bash
npm run dev
```

### Optional modules with a local Supabase (#1061)

`ReconciliationModule`, `NotificationsModule` and `DeveloperModule` are loaded
according to explicit flags in `app/backend/.env`, never based on whether
`SUPABASE_URL` points at `localhost` / `127.0.0.1`. To exercise them against a
local Supabase instance:

```bash
# app/backend/.env
SUPABASE_URL=http://127.0.0.1:54321
ENABLE_RECONCILIATION_MODULE=true
ENABLE_NOTIFICATIONS_MODULE=true
ENABLE_DEVELOPER_MODULE=true
```

- Unset flags default to `true`, so a fresh `.env` loads all three modules.
- Only `true` / `false` are accepted; any other value stops startup with a
  config error instead of silently changing which modules load.
- `ENABLE_DEVELOPER_MODULE=false` leaves out the developer portal endpoints.
- `ENABLE_RECONCILIATION_MODULE` and `ENABLE_NOTIFICATIONS_MODULE` cannot be
  `false` yet: `JobQueueModule`, `FiatRampsModule` and `OperationsModule` import
  them directly, so they always start. Startup rejects `false` for them with
  an explanation rather than pretending they are off. To stop reconciliation's
  scheduled runs locally, use the existing `RECONCILIATION_ENABLED=false`.
- Migration note: local setups previously skipped `DeveloperModule` (the other
  two were already loaded through those imports). It now loads locally too;
  set `ENABLE_DEVELOPER_MODULE=false` to keep the old behaviour.

---

## Rust Contracts

Compile contracts.

```bash
cargo build
```

Execute tests.

```bash
cargo test
```

Lint.

```bash
cargo clippy --all-targets --all-features
```

Format.

```bash
cargo fmt
```

---

## Before Opening a Pull Request

Verify that:

- The project builds successfully.
- Database migrations are up to date.
- Rust tests pass.
- TypeScript tests pass.
- Linting passes.
- Formatting passes.
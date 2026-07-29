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
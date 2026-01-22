# Contributing (Backend)

## API standards

- DTO validation is required for request bodies.
- Use `class-validator` + `class-transformer`.
- Prefer explicit status codes and predictable response shapes.
- Do not log secrets (never print Supabase keys).

## DTO rules

- Enforce `whitelist: true` and `forbidNonWhitelisted: true`.
- Keep DTOs small and versionable.

## Testing

Run tests from repo root:

```bash
pnpm turbo run test --filter=@quickex/backend
```

Add tests for new endpoints (happy path + validation/error path).

## PR checklist

- Endpoints documented (README updates if needed)
- DTO validation added/updated
- Unit/integration tests added and passing
- `pnpm turbo run type-check --filter=@quickex/backend` passes
- `pnpm turbo run lint --filter=@quickex/backend` passes

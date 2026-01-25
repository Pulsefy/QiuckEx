# Contributing (Backend)

## API standards

- DTO validation is required for request bodies.
- Use `class-validator` + `class-transformer`.
- Prefer explicit status codes and predictable response shapes.
- Do not log secrets (never print Supabase keys).

## DTO rules

- Enforce `whitelist: true` and `forbidNonWhitelisted: true`.
- Keep DTOs small and versionable.

## Stellar assets and network

- Supported assets live in `src/config/stellar.config.ts` under `SUPPORTED_ASSETS`.
- Native assets use `{ type: 'native', code: 'XLM' }`.
- Issued assets require an exact issuer (case-sensitive).

Example issued asset entry:

```ts
{
  type: 'credit_alphanum4',
  code: 'EURT',
  issuer: 'GEXAMPLEISSUERADDRESS'
}
```

Network configuration:

- Env var: `STELLAR_NETWORK`
- Allowed: `testnet`, `mainnet`
- Default: `testnet`
- Invalid values throw `InvalidNetworkError` at startup.

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

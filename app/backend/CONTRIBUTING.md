# Contributing (Backend)

## Branch Strategy
- Use `feature/` for new features (e.g., `feature/add-payment-intent`).
- Use `fix/` for bug fixes (e.g., `fix/validation-error`).
- Use `docs/` for documentation updates (e.g., `docs/update-readme`).

## API standards

- **DTO Validation**: Required for all request bodies.
- **Libraries**: Use `class-validator` + `class-transformer`.
- **Responses**: Prefer explicit status codes and predictable response shapes.
- **Security**: Do not log secrets (never print Supabase keys).

## DTO rules

- Enforce `whitelist: true` and `forbidNonWhitelisted: true` in the global validation pipe.
- Keep DTOs small and versionable.
- **Example**:
  ```typescript
  export class CreateUsernameDto {
    @IsString()
    @IsNotEmpty()
    @Length(3, 32)
    @Matches(/^[a-z0-9_]+$/)
    username!: string;
  }
  ```

## Testing

Run tests from repo root:

```bash
pnpm turbo run test --filter=@quickex/backend
```

- **Requirement**: Add tests for new endpoints (happy path + validation/error path).
- **Type Check**: Ensure `pnpm turbo run type-check --filter=@quickex/backend` passes.

## PR checklist

- [ ] Endpoints documented (README updates if needed)
- [ ] DTO validation added/updated
- [ ] Unit/integration tests added and passing
- [ ] `pnpm turbo run type-check --filter=@quickex/backend` passes
- [ ] `pnpm turbo run lint --filter=@quickex/backend` passes
- [ ] Commits are signed off (DCO compliance)
- [ ] PR description includes "Closes #<issue_id>"

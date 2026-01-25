# Contributing (Backend)

## API Versioning Policy

All API endpoints must be versioned using the `@Version()` decorator.

**Rules:**
- Use URI versioning (e.g., `/v1/health`)
- Default version is `v1` (configured in `main.ts`)
- Always add `@Version('1')` to new route handlers
- When introducing breaking changes, increment the version (e.g., `@Version('2')`)

**Example:**
```typescript
@Controller('example')
export class ExampleController {
  @Get()
  @Version('1')
  getExample() {
    return { data: 'example' };
  }
}
```

This creates the route: `GET /v1/example`

## API standards

- DTO validation is required for request bodies.
- Use `class-validator` + `class-transformer`.
- Prefer explicit status codes and predictable response shapes.
- Do not log secrets (never print Supabase keys).

## DTO rules and Validation Patterns

The backend uses a **global ValidationPipe** with strict options:
- `whitelist: true` - Strips non-whitelisted properties
- `forbidNonWhitelisted: true` - Rejects requests with extra properties
- `transform: true` - Automatically transforms request bodies to DTO instances

**Best Practices:**
- Always define DTOs with `class-validator` decorators
- Use appropriate validators: `@IsString()`, `@IsNotEmpty()`, `@Length()`, `@Matches()`, etc.
- Keep DTOs small and focused
- DTOs should be versionable (consider creating new DTOs for new API versions)

**Example DTO:**
```typescript
import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class CreateUsernameDto {
  @IsString()
  @IsNotEmpty()
  @Length(3, 32)
  @Matches(/^[a-z0-9_]+$/)
  username!: string;
}
```

**Validation Error Response Shape:**
When validation fails, NestJS returns a 400 Bad Request with this structure:
```json
{
  "statusCode": 400,
  "message": ["error message 1", "error message 2"],
  "error": "Bad Request"
}
```

## CORS Configuration

- CORS origins are explicitly whitelisted (no wildcards in production)
- Update `allowedOrigins` in `src/main.ts` when adding new allowed domains
- Never use `origin: true` or `origin: '*'` in production

## Testing

Run tests from repo root:

```bash
pnpm turbo run test --filter=@quickex/backend
```

Add tests for new endpoints (happy path + validation/error path).

**Test Validation:**
- Test with valid payloads → expect 200
- Test with extra fields → expect 400
- Test with wrong types → expect 400
- Test with missing required fields → expect 400

## PR checklist

- Endpoints documented (README updates if needed)
- DTO validation added/updated
- Version decorator added to new routes (`@Version('1')`)
- Unit/integration tests added and passing
- `pnpm turbo run type-check --filter=@quickex/backend` passes
- `pnpm turbo run lint --filter=@quickex/backend` passes

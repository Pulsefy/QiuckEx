# Contributing (Backend)

This guide covers contribution standards for the QuickEx backend.

## Quick Start

### 1. Setup

```bash
# Install dependencies from repo root
pnpm install

# Copy environment template
cp app/backend/.env.example app/backend/.env

# Fill in required environment variables (see README.md for details)
```

### 2. Required Environment Variables

The backend validates environment variables at startup. You must configure:

| Variable           | Description                              |
| ------------------ | ---------------------------------------- |
| `NETWORK`          | `testnet` or `mainnet`                   |
| `SUPABASE_URL`     | Your Supabase project URL                |
| `SUPABASE_ANON_KEY`| Your Supabase anonymous key              |

**Validation behavior:**
- Missing required variables → Clear error message listing all missing keys → Exit code 1
- Invalid values → Descriptive error explaining the constraint → Exit code 1
- All valid → Application starts normally

### 3. Run Development Server

```bash
pnpm turbo run dev --filter=@quickex/backend
```

Server starts at `http://localhost:4000` with API docs at `http://localhost:4000/docs`.

## API Standards

### Request Validation

- DTO validation is **required** for all request bodies
- Use `class-validator` + `class-transformer` decorators
- Global `ValidationPipe` enforces:
  - `whitelist: true` - Strip unknown properties
  - `forbidNonWhitelisted: true` - Reject requests with unknown properties
  - `transform: true` - Auto-transform payloads to DTO instances

### Response Standards

- Use explicit HTTP status codes
- Return predictable response shapes
- Document all responses in Swagger

### Security

- **Never log secret values** (keys, tokens, passwords)
- Only log key names in error messages
- Mark authentication-required endpoints in Swagger

## Swagger/OpenAPI Documentation

All endpoints must be documented using `@nestjs/swagger` decorators.

### Required Decorators

#### Controllers

```typescript
import { Controller, Get, Post, Body } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';

@ApiTags('feature-name')  // Group endpoints by feature
@Controller('feature')
export class FeatureController {

  @Get()
  @ApiOperation({
    summary: 'Short description',
    description: 'Detailed description of what this endpoint does',
  })
  @ApiResponse({ status: 200, description: 'Success', type: ResponseDto })
  @ApiResponse({ status: 400, description: 'Bad request' })
  getFeature() { ... }

  @Post()
  @ApiOperation({ summary: 'Create feature' })
  @ApiBody({ type: CreateFeatureDto })
  @ApiResponse({ status: 201, description: 'Created', type: ResponseDto })
  @ApiResponse({ status: 400, description: 'Validation failed' })
  createFeature(@Body() dto: CreateFeatureDto) { ... }
}
```

#### DTOs

```typescript
import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, Length } from 'class-validator';

export class CreateFeatureDto {
  @ApiProperty({
    description: 'What this field represents',
    example: 'example_value',
    minLength: 3,
    maxLength: 32,
  })
  @IsString()
  @IsNotEmpty()
  @Length(3, 32)
  fieldName!: string;
}
```

#### Response DTOs

```typescript
import { ApiProperty } from '@nestjs/swagger';

export class FeatureResponseDto {
  @ApiProperty({
    description: 'Response field description',
    example: true,
  })
  success!: boolean;
}
```

### Swagger Best Practices

1. **Always add `@ApiTags()`** to controllers for grouping
2. **Always add `@ApiOperation()`** with summary and description
3. **Always add `@ApiResponse()`** for all possible status codes
4. **Always add `@ApiProperty()`** to DTO fields with examples
5. **Use meaningful examples** that demonstrate valid inputs
6. **Document validation constraints** in the description
7. **Never expose sensitive headers** in documentation

### Accessing API Docs

- **Swagger UI:** `http://localhost:4000/docs`
- **OpenAPI JSON:** `http://localhost:4000/docs-json`

## Shared DTO Library

The backend uses a centralized DTO library located at `src/dto/` to ensure consistency across endpoints and avoid duplicate definitions.

### Library Structure

```
src/dto/
├── username/          # Username-related DTOs
├── link/             # Payment link metadata DTOs
├── transaction/      # Transaction query DTOs
├── validators/       # Reusable validation decorators
└── index.ts          # Barrel export
```

### Using Shared DTOs

**Import DTOs from the shared library:**

```typescript
import {
  CreateUsernameDto,
  CreateUsernameResponseDto,
  LinkMetadataRequestDto,
  LinkMetadataResponseDto,
  TransactionQueryDto,
  ScanLinkDto,
} from '../dto';
```

**Import validators:**

```typescript
import {
  IsUsername,
  IsStellarPublicKey,
  IsStellarAmount,
  IsStellarMemo,
  IsStellarAsset,
} from '../dto/validators';
```

### Example: Using Shared DTOs in Controllers

```typescript
import { Controller, Post, Body } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { CreateUsernameDto, CreateUsernameResponseDto } from '../dto';

@ApiTags('usernames')
@Controller('username')
export class UsernamesController {
  @Post()
  @ApiOperation({ summary: 'Create a new username' })
  @ApiResponse({ status: 201, type: CreateUsernameResponseDto })
  createUsername(@Body() dto: CreateUsernameDto): CreateUsernameResponseDto {
    // Implementation
    return { ok: true };
  }
}
```

### Example: Creating Custom DTOs with Shared Validators

```typescript
import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';
import { IsUsername, IsStellarPublicKey } from '../dto/validators';

export class CustomUserDto {
  @ApiProperty({ example: 'alice_123' })
  @IsString()
  @IsNotEmpty()
  @IsUsername()
  username!: string;

  @ApiProperty({ example: 'GBXGQ...' })
  @IsString()
  @IsNotEmpty()
  @IsStellarPublicKey()
  publicKey!: string;
}
```

### Available Validators

| Validator | Description | Example |
|-----------|-------------|---------|
| `@IsUsername()` | Validates username format (3-32 chars, lowercase alphanumeric + underscore) | `alice_123` |
| `@IsStellarPublicKey()` | Validates Stellar public key (G... 56 chars) | `GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR` |
| `@IsStellarAmount()` | Validates amount within Stellar limits (0.0000001 - 1,000,000) | `100.5` |
| `@IsStellarMemo()` | Validates memo length (max 28 chars) | `Payment for service` |
| `@IsStellarAsset()` | Validates asset code against whitelist | `XLM`, `USDC`, `AQUA`, `yXLM` |

### Available DTOs

#### Username DTOs
- `CreateUsernameDto` - Request DTO for username creation
- `CreateUsernameResponseDto` - Response DTO for username creation

#### Link DTOs
- `LinkMetadataRequestDto` - Request DTO for link metadata generation
- `LinkMetadataResponseDto` - Response DTO for link metadata
- `ScanLinkDto` - Request DTO for scanning payment links

#### Transaction DTOs
- `TransactionQueryDto` - Query DTO for transaction filtering and pagination
- `TransactionResponseDto` - Response DTO for transaction queries
- `TransactionDto` - Individual transaction in response

### DTO Rules

### Validation Requirements

```typescript
// Good: Using shared validators with descriptive messages
import { IsUsername, IsStellarPublicKey } from '../dto/validators';

export class CreateUserDto {
  @IsString()
  @IsNotEmpty()
  @IsUsername({
    message: 'Username must contain only lowercase letters, numbers, and underscores',
  })
  username!: string;

  @IsString()
  @IsNotEmpty()
  @IsStellarPublicKey()
  publicKey!: string;
}

// Bad: Missing validation or duplicate definitions
export class BadDto {
  username: string; // No validation
}
```

### Guidelines

- **Always use shared DTOs** from `src/dto/` instead of creating duplicates
- **Use shared validators** for common validation patterns
- Enforce `whitelist: true` and `forbidNonWhitelisted: true`
- Keep DTOs small and focused
- Use descriptive validation messages
- Add `@ApiProperty()` to all fields
- **Single source of truth**: All common DTOs should be in the shared library

### Link Validation Rules

When working with payment link features, follow these validation constraints:

#### Amount Validation
- Minimum: 0.0000001 XLM (Stellar minimum)
- Maximum: 1,000,000 XLM
- Precision: 7 decimal places (Stellar standard)
- Normalized automatically to 7 decimals

#### Memo Validation
- Maximum length: 28 characters (Stellar limit)
- Allowed types: 'text', 'id', 'hash', 'return'
- Sanitization: Removes <, >, ", ' characters
- Whitespace: Trimmed automatically

#### Asset Validation
- Whitelist enforcement: Only approved assets accepted
- Current whitelist: XLM, USDC, AQUA, yXLM
- Default: XLM if not specified

#### Security Considerations
- All memos are sanitized to prevent injection attacks
- Input validation occurs before any processing
- Clear error messages for debugging
- No sensitive data in error responses

## Configuration

### Adding New Environment Variables

1. **Update the Joi schema** in `src/config/env.schema.ts`:

```typescript
export const envSchema = Joi.object({
  // ... existing vars
  NEW_VAR: Joi.string().required().description('Description'),
});

export interface EnvConfig {
  // ... existing types
  NEW_VAR: string;
}
```

2. **Add typed accessor** in `src/config/app-config.service.ts`:

```typescript
get newVar(): string {
  return this.configService.get('NEW_VAR', { infer: true });
}
```

3. **Update `.env.example`** with documentation:

```env
# Description of what this variable does
NEW_VAR=example_value
```

4. **Update `README.md`** environment table

## Testing

### Run Tests

```bash
pnpm turbo run test --filter=@quickex/backend
```

### Test Requirements

Add tests for:
- **Happy path:** Valid inputs produce expected outputs
- **Validation errors:** Invalid inputs return appropriate errors
- **Edge cases:** Boundary conditions, empty values, etc.

### Schema Validation Tests

Environment schema tests are in `src/config/env.schema.spec.ts`. When adding new env vars, add tests for:
- Valid values are accepted
- Missing required values are rejected with clear messages
- Invalid values are rejected with clear messages

## PR Checklist

Before submitting a PR, ensure:

- [ ] Environment variables documented in `README.md` and `.env.example`
- [ ] Swagger decorators added to new endpoints and DTOs
- [ ] DTO validation added/updated with descriptive messages
- [ ] Unit/integration tests added and passing
- [ ] Schema validation tests added for new env vars
- [ ] `pnpm turbo run type-check --filter=@quickex/backend` passes
- [ ] `pnpm turbo run lint --filter=@quickex/backend` passes
- [ ] `pnpm turbo run test --filter=@quickex/backend` passes
- [ ] API docs updated (verify at `/docs`)

## Common Commands

```bash
# Development
pnpm turbo run dev --filter=@quickex/backend

# Testing
pnpm turbo run test --filter=@quickex/backend

# Type checking
pnpm turbo run type-check --filter=@quickex/backend

# Linting
pnpm turbo run lint --filter=@quickex/backend

# Build
pnpm turbo run build --filter=@quickex/backend
```

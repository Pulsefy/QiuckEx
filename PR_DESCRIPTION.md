# Backend: API Versioning, CORS, and Global Validation Documentation

## Summary

This PR introduces API versioning (v1), configures CORS with safe defaults, and documents the existing global ValidationPipe configuration. These changes enable stable API evolution and secure cross-origin requests for frontend and future public clients.

## Changes

### 🔢 API Versioning (v1)

- **Enabled URI versioning** in `main.ts` with default version `v1`
- **Applied `@Version('1')` decorator** to all existing controllers:
  - `HealthController` - `GET /v1/health`
  - `UsernamesController` - `POST /v1/username`
- All routes now require the `/v1/` prefix for explicit versioning

**Configuration:**
```typescript
app.enableVersioning({
  type: VersioningType.URI,
  defaultVersion: '1',
});
```

### 🔒 CORS Configuration

- **Replaced permissive `origin: true`** with explicit allowlist
- **Allowed origins:**
  - `http://localhost:3000` (local frontend development)
  - `https://app.quickex.example.com` (placeholder for production - update before deploy)
- **Configured methods:** GET, POST, PUT, PATCH, DELETE, OPTIONS
- **Credentials enabled** for authenticated requests
- **Allows no-origin requests** (mobile apps, curl, Postman)

**Security:** No wildcard origins; explicit allowlist prevents unauthorized access.

### ✅ Global Validation Pipe

- **Documented existing strict validation** configuration:
  - `whitelist: true` - Strips non-whitelisted properties
  - `forbidNonWhitelisted: true` - Rejects requests with extra fields
  - `transform: true` - Auto-transforms request bodies to DTOs
- **Added validation examples** in README showing error responses

### 📚 Documentation Updates

**`app/backend/README.md`:**
- Added API versioning section with route examples
- Added request validation section with valid/invalid examples
- Added CORS configuration details
- Updated endpoint examples to use `/v1/` prefix

**`app/backend/CONTRIBUTING.md`:**
- Added API versioning policy and `@Version()` usage guidelines
- Added DTO validation patterns and best practices
- Added validation error response shape documentation
- Added CORS configuration guidelines

## Testing

### Manual Testing

```bash
# Test versioned health endpoint
curl http://localhost:4000/v1/health
# Expected: { "status": "ok" }

# Test validation with valid request
curl -X POST http://localhost:4000/v1/username \
  -H "Content-Type: application/json" \
  -d '{"username": "alice123"}'
# Expected: { "ok": true }

# Test validation with extra field (should return 400)
curl -X POST http://localhost:4000/v1/username \
  -H "Content-Type: application/json" \
  -d '{"username": "alice123", "extra": "field"}'
# Expected: 400 Bad Request with validation error

# Test CORS from localhost:3000 (should succeed)
# Test CORS from other origin (should fail)
```

### Browser Testing

- Frontend requests from `http://localhost:3000` should succeed
- Requests from other origins should be blocked by CORS

## Migration Notes

⚠️ **Breaking Change:** All API endpoints now require the `/v1/` prefix:
- `GET /health` → `GET /v1/health`
- `POST /username` → `POST /v1/username`

Update frontend and any API clients to use versioned routes.

## Production Checklist

- [ ] Update `allowedOrigins` in `src/main.ts` with actual production domain
- [ ] Replace `https://app.quickex.example.com` placeholder
- [ ] Verify CORS configuration works with production frontend
- [ ] Update API documentation with versioned endpoints

## Files Changed

- `app/backend/src/main.ts` - Added versioning, updated CORS, documented validation
- `app/backend/src/health/health.controller.ts` - Added `@Version('1')`
- `app/backend/src/usernames/usernames.controller.ts` - Added `@Version('1')`
- `app/backend/README.md` - Added versioning, validation, and CORS docs
- `app/backend/CONTRIBUTING.md` - Added versioning policy and validation patterns

## Related Issues

Closes #[issue_id]

---

**Commit Message:**
```
chore(backend): enable API versioning and CORS defaults

- Enable URI versioning with default v1
- Configure CORS with explicit origin allowlist
- Document global ValidationPipe configuration
- Update README and CONTRIBUTING with versioning policy
```

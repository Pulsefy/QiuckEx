# Crash Reporting Quick Start Guide

## For Users

### Enable Crash Reporting

```bash
curl -X PUT http://localhost:4000/crash-reporting/settings/YOUR_USER_ID \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

### Check Your Settings

```bash
curl http://localhost:4000/crash-reporting/settings/YOUR_USER_ID
```

### Export Logs for Support

```bash
curl http://localhost:4000/crash-reporting/export/YOUR_USER_ID > my-logs.json
```

### View Your Crash Reports

```bash
curl http://localhost:4000/crash-reporting/reports/YOUR_USER_ID
```

### Disable Crash Reporting

```bash
curl -X PUT http://localhost:4000/crash-reporting/settings/YOUR_USER_ID \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

## For Developers

### Manual Crash Capture

```typescript
import { CrashReportingService } from './crash-reporting';

// In your service/controller
constructor(
  private readonly crashReportingService: CrashReportingService,
) {}

// Capture a crash
try {
  await riskyOperation();
} catch (error) {
  await this.crashReportingService.captureCrash(
    userId,
    error,
    { 
      operation: 'payment',
      amount: 100,
      // Don't include sensitive data - it will be redacted anyway
    }
  );
  throw error;
}
```

### Check If User Has Opted In

```typescript
const settings = await this.crashReportingService.getUserSettings(userId);
if (settings?.crashReportingEnabled) {
  // User has opted in
}
```

### Capture Log Lines

```typescript
// Log lines are automatically captured by LogCaptureInterceptor
// Or manually:
this.crashReportingService.captureLogLine('Important operation started');
```

### Test Redaction

```typescript
import { RedactionService } from './crash-reporting';

const redactionService = new RedactionService();

// Test string redaction
const redacted = redactionService.redact('My key is GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H');
console.log(redacted); // "My key is [REDACTED_PUBLIC_KEY]"

// Test object redaction
const redactedObj = redactionService.redactObject({
  email: 'user@example.com',
  apiKey: 'test_key_abc123',
  normalField: 'safe',
});
console.log(redactedObj);
// { email: '[REDACTED_EMAIL]', apiKey: '[REDACTED]', normalField: 'safe' }
```

## Database Setup

### Run Migration

```bash
# Using psql
psql -U postgres -d quickex -f src/crash-reporting/migrations/001_create_crash_reporting_tables.sql

# Or using Supabase CLI
supabase db push
```

### Verify Tables

```sql
-- Check if tables exist
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN ('crash_reports', 'crash_reporting_settings');

-- Check RLS policies
SELECT tablename, policyname FROM pg_policies 
WHERE tablename IN ('crash_reports', 'crash_reporting_settings');
```

## Testing

### Run All Tests

```bash
npm run test:unit -- --testPathPattern=crash-reporting
```

### Run Specific Tests

```bash
# Redaction tests
npm run test:unit -- --testPathPattern=redaction.service.spec.ts

# Service tests
npm run test:unit -- --testPathPattern=crash-reporting.service.spec.ts

# Integration tests
npm run test:int -- --testPathPattern=crash-reporting.integration.spec.ts
```

### Manual Testing

```typescript
// Test that secrets are never leaked
const testCases = [
  'SBZVMB74Z76QZ3ZOY3XRXEPNQN754WKRGMAG4OQIPOOB6QMHIDCNVYKY', // Stellar secret
  'test_key_1234567890abcdefghijklmnop', // API key
  'user@example.com', // Email
  '192.168.1.1', // IP
];

testCases.forEach(sensitive => {
  const redacted = redactionService.redact(`Test: ${sensitive}`);
  if (redacted.includes(sensitive)) {
    console.error('LEAK DETECTED:', sensitive);
  } else {
    console.log('✓ Redacted successfully');
  }
});
```

## Common Issues

### Issue: Crash reports not being captured

**Solution**: Check if user has opted in:
```typescript
const settings = await crashReportingService.getUserSettings(userId);
console.log('Opted in:', settings?.crashReportingEnabled);
```

### Issue: Sensitive data appearing in logs

**Solution**: This should never happen. If it does:
1. Check the redaction patterns in `redaction.service.ts`
2. Add a new pattern if needed
3. Add a test case to prevent regression
4. Report the issue immediately

### Issue: Export returns null

**Solution**: User must opt in first:
```bash
curl -X PUT http://localhost:4000/crash-reporting/settings/USER_ID \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'
```

## Best Practices

1. **Never log sensitive data directly** - The redaction service will catch it, but it's better to avoid it
2. **Always check opt-in status** before capturing crashes manually
3. **Use structured context** when capturing crashes for better debugging
4. **Regularly clean up old reports** using `repository.deleteOldReports(90)`
5. **Test redaction patterns** when adding new sensitive data types
6. **Monitor log buffer size** in production (max 100 lines)

## What Gets Redacted

✅ **Always Redacted:**
- Stellar keys (G... and S...)
- API keys and tokens
- Passwords
- JWT tokens
- Email addresses
- IP addresses
- Phone numbers
- Credit card numbers
- Database connection strings
- Authorization headers

✅ **Preserved:**
- Request IDs
- HTTP methods and paths
- Status codes
- Timestamps
- Non-sensitive context data

## Support

For issues or questions:
1. Check the [README.md](./README.md) for detailed documentation
2. Review the [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md)
3. Run the tests to validate your setup
4. Check the test files for usage examples

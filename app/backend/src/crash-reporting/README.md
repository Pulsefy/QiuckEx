# Crash Reporting Module

## Overview

The Crash Reporting module provides opt-in crash and log capture with strict redaction to help debug production issues without compromising user privacy. All captured data is automatically redacted to remove secrets, keys, and personally identifiable information (PII).

## Features

- **Opt-in by default**: Users must explicitly enable crash reporting
- **Strict redaction**: Automatically removes secrets, keys, and PII from all captured data
- **Log capture**: Captures the last 100 log lines before a crash
- **Export functionality**: Users can export their logs for support
- **Privacy-first**: No sensitive data is ever stored or transmitted

## Architecture

### Components

1. **RedactionService**: Core service that redacts sensitive information
2. **CrashReportingService**: Main service for capturing crashes and managing settings
3. **CrashReportingRepository**: Data persistence layer
4. **CrashCaptureFilter**: Global exception filter that automatically captures crashes
5. **LogCaptureInterceptor**: Interceptor that captures log lines

### Data Flow

```
Request → LogCaptureInterceptor → Controller → Service
                ↓                                  ↓
         Capture log line                    Exception thrown
                ↓                                  ↓
         Log buffer                    CrashCaptureFilter
                ↓                                  ↓
         (stored in memory)            Check user opt-in
                                                   ↓
                                        Redact sensitive data
                                                   ↓
                                        Store crash report
```

## Redaction Rules

The RedactionService automatically redacts:

### Secrets and Keys
- Stellar public keys (G...)
- Stellar secret keys (S...)
- API keys
- Bearer tokens
- JWT tokens
- Passwords
- Authorization headers
- Database connection strings

### Personally Identifiable Information (PII)
- Email addresses
- IP addresses (IPv4 and IPv6)
- Phone numbers
- Credit card numbers

### Environment Variables
- All sensitive environment variable values (STELLAR_SECRET_KEY, API_KEYS, etc.)

## Usage

### Enable Crash Reporting for a User

```typescript
await crashReportingService.updateUserSettings('user-123', true);
```

### Capture a Crash Manually

```typescript
try {
  // Some operation
} catch (error) {
  await crashReportingService.captureCrash(
    userId,
    error,
    { route: '/api/payments', method: 'POST' }
  );
}
```

### Export Logs for Support

```typescript
const logExport = await crashReportingService.exportLogs('user-123');
// Returns null if user has not opted in
```

### Get User's Crash Reports

```typescript
const reports = await crashReportingService.getCrashReports('user-123', 10);
```

## API Endpoints

### Get Settings
```
GET /crash-reporting/settings/:userId
```

Returns the user's crash reporting settings.

### Update Settings
```
PUT /crash-reporting/settings/:userId
Body: { "enabled": true }
```

Updates the user's crash reporting settings.

### Export Logs
```
GET /crash-reporting/export/:userId
```

Exports logs for support (requires opt-in).

### Get Crash Reports
```
GET /crash-reporting/reports/:userId
```

Returns the user's crash reports (requires opt-in).

## Database Schema

### crash_reports
- `id`: UUID (primary key)
- `user_id`: TEXT (nullable)
- `error`: JSONB (redacted error information)
- `context`: JSONB (redacted context)
- `log_lines`: TEXT[] (redacted log lines)
- `timestamp`: TIMESTAMPTZ
- `created_at`: TIMESTAMPTZ

### crash_reporting_settings
- `user_id`: TEXT (primary key)
- `crash_reporting_enabled`: BOOLEAN (default: false)
- `updated_at`: TIMESTAMPTZ

## Security Considerations

### Row Level Security (RLS)
Both tables have RLS enabled:
- Users can only read their own crash reports
- Users can only read/update their own settings
- Service role can insert crash reports

### Data Retention
Crash reports should be periodically cleaned up:

```typescript
// Delete reports older than 90 days
await repository.deleteOldReports(90);
```

### Redaction Validation
The module includes comprehensive tests to ensure redaction works correctly:
- `redaction.service.spec.ts`: Tests all redaction patterns
- `crash-reporting.service.spec.ts`: Tests end-to-end crash capture with redaction

## Testing

Run the redaction tests:
```bash
npm test -- redaction.service.spec.ts
```

Run the crash reporting tests:
```bash
npm test -- crash-reporting.service.spec.ts
```

## Configuration

### Environment Variables

No additional environment variables are required. The module uses the existing Supabase configuration.

### Feature Flags

The crash reporting feature is disabled by default and requires explicit user opt-in.

### Development Mode

In development mode, you may want to disable automatic crash capture:

```typescript
// In app.module.ts
if (process.env.NODE_ENV !== 'production') {
  // Don't register CrashCaptureFilter
}
```

## Integration

### Add to App Module

```typescript
import { CrashReportingModule } from './crash-reporting/crash-reporting.module';

@Module({
  imports: [
    // ... other modules
    CrashReportingModule,
  ],
})
export class AppModule {}
```

### Register Global Filter (Optional)

```typescript
import { APP_FILTER } from '@nestjs/core';
import { CrashCaptureFilter } from './crash-reporting/crash-capture.filter';

@Module({
  providers: [
    {
      provide: APP_FILTER,
      useClass: CrashCaptureFilter,
    },
  ],
})
export class AppModule {}
```

### Register Global Interceptor (Optional)

```typescript
import { APP_INTERCEPTOR } from '@nestjs/core';
import { LogCaptureInterceptor } from './crash-reporting/log-capture.interceptor';

@Module({
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: LogCaptureInterceptor,
    },
  ],
})
export class AppModule {}
```

## Acceptance Criteria

✅ **Logs are redacted reliably and never include secrets**
- Comprehensive redaction patterns for all sensitive data types
- Extensive test coverage validating redaction behavior
- Multiple layers of redaction (strings, objects, errors, log lines)

✅ **Users can export logs for support when opted-in**
- Export endpoint requires opt-in
- Returns redacted logs and crash reports
- Includes current log buffer and historical crash reports

✅ **Feature is disabled by default**
- Users must explicitly opt-in via settings
- No data is captured without consent
- Crash capture checks opt-in status before storing data

## Future Enhancements

- Add support for log streaming to external services (with redaction)
- Implement automatic crash report aggregation and analysis
- Add support for custom redaction patterns per deployment
- Implement log sampling for high-traffic scenarios
- Add support for structured logging with automatic field redaction

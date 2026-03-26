# Recurring Payment Link Engine - Implementation Guide

## Overview

The Recurring Payment Link Engine enables subscription-style payments on Stellar, allowing users to create payment links that automatically execute at regular intervals (daily, weekly, monthly, or yearly).

## Features

### Core Capabilities

- **Recurring Link Creation**: Create subscription payment links with configurable frequency and duration
- **Automated Execution**: Cron-based scheduler executes payments automatically
- **Payment Tracking**: Track each payment period with detailed execution history
- **Status Management**: Pause, resume, or cancel recurring links
- **Notification Integration**: Automated alerts for due, successful, and failed payments
- **Retry Logic**: Automatic retry mechanism for failed payments (configurable retries)

### Supported Frequencies

- Daily
- Weekly
- Monthly
- Yearly

## Architecture

### Database Schema

Two main tables manage recurring payments:

1. **recurring_payment_links**: Stores link configurations
   - Payment details (amount, asset, frequency)
   - Schedule (start_date, end_date, total_periods)
   - Status tracking (active, paused, completed, cancelled)
   - Execution metadata

2. **recurring_payment_executions**: Tracks individual payment executions
   - Period number and scheduling
   - Execution status (pending, success, failed, skipped)
   - Transaction hash and failure reasons
   - Retry count and notification tracking

### Key Components

#### 1. DTOs (`src/links/dto/recurring-payment.dto.ts`)

TypeScript interfaces and validation classes:
- `CreateRecurringPaymentLinkDto`: Input validation
- `UpdateRecurringPaymentLinkDto`: Partial updates
- `RecurringPaymentLinkResponseDto`: Response format
- `RecurringPaymentExecutionDto`: Execution details
- Enums: `FrequencyType`, `RecurringStatus`, `ExecutionStatus`

#### 2. Repository (`src/links/recurring-payments.repository.ts`)

Database operations using Supabase:
- CRUD operations for links and executions
- Query optimization with indexes
- Transaction support

#### 3. Service (`src/links/recurring-payments.service.ts`)

Business logic layer:
- Link creation and validation
- Status management (cancel, pause, resume)
- Execution tracking
- Event emission

#### 4. Scheduler (`src/links/recurring-payments.scheduler.ts`)

Automated execution engine:
- Cron job runs every minute
- Identifies due payments
- Executes payments via Stellar processor
- Handles success/failure scenarios
- Emits notification events

#### 5. Stellar Processor (`src/stellar/recurring-payment-processor.ts`)

Blockchain transaction handler:
- Builds and signs payment transactions
- Submits to Stellar network
- Supports native XLM and custom assets (USDC, etc.)
- Transaction verification

#### 6. Controller (`src/links/recurring-payments.controller.ts`)

REST API endpoints:
- `POST /links/recurring` - Create link
- `GET /links/recurring/:id` - Get link details
- `GET /links/recurring` - List links (with filters)
- `PATCH /links/recurring/:id` - Update link
- `POST /links/recurring/:id/cancel` - Cancel
- `POST /links/recurring/:id/pause` - Pause
- `POST /links/recurring/:id/resume` - Resume
- `GET /links/recurring/:id/executions` - Execution history

## API Usage Examples

### Create a Recurring Payment Link

```typescript
POST /links/recurring
{
  "amount": 100,
  "asset": "XLM",
  "frequency": "monthly",
  "username": "john_doe",
  "startDate": "2025-04-01T00:00:00Z",
  "totalPeriods": 12,
  "memo": "Monthly subscription",
  "privacyEnabled": false
}
```

Response:
```json
{
  "success": true,
  "data": {
    "id": "uuid-here",
    "username": "john_doe",
    "amount": 100,
    "asset": "XLM",
    "frequency": "monthly",
    "status": "active",
    "executedCount": 0,
    "nextExecutionDate": "2025-04-01T00:00:00Z",
    "createdAt": "2025-03-26T00:00:00Z"
  }
}
```

### List Recurring Links

```typescript
GET /links/recurring?status=active&username=john_doe&page=1&limit=20
```

### Pause a Link

```typescript
POST /links/recurring/{id}/pause
```

### Get Execution History

```typescript
GET /links/recurring/{id}/executions
```

## Configuration

### Environment Variables

Add to `.env`:

```env
# Recurring Payments Configuration
RECURRING_PAYMENT_MAX_RETRY=3
RECURRING_PAYMENT_RETRY_BACKOFF_MS=60000
RECURRING_PAYMENT_NOTIFICATION_HOURS_BEFORE=24
STELLAR_SECRET_KEY=your-secret-key-here
```

### Scheduler Configuration

The scheduler runs automatically when the application starts. It checks for pending payments every minute:

- `@Cron(CronExpression.EVERY_MINUTE)` - Execute pending payments
- `@Cron(CronExpression.EVERY_HOUR)` - Send upcoming payment notifications

## Notification Events

The system emits the following events:

- `recurring.link.created` - New link created
- `recurring.link.updated` - Link updated
- `recurring.link.cancelled` - Link cancelled
- `recurring.link.paused` - Link paused
- `recurring.link.resumed` - Link resumed
- `recurring.link.completed` - Link completed (all periods executed)
- `recurring.payment.due` - Payment due soon (24h before)
- `recurring.payment.executed` - Payment executed successfully
- `recurring.payment.failed` - Payment failed (with retry info)

These events integrate with the existing notification engine to send emails, push notifications, or webhook callbacks.

## Error Handling

### Validation Errors

- Missing username or destination
- Invalid amount (must be > 0)
- Invalid frequency type
- Start date in the past
- End date before start date
- Total periods <= 0

### Execution Errors

- Insufficient funds in platform account
- Invalid recipient address
- Network errors
- Stellar transaction failures

Failed payments are retried up to `RECURRING_PAYMENT_MAX_RETRY` times with exponential backoff.

## Testing

Run tests:

```bash
# Unit tests
npm run test:unit -- recurring-payments

# Integration tests
npm run test:int -- recurring-payments

# E2E tests
npm run test:e2e -- recurring-payments.controller.e2e-spec.ts
```

## Monitoring

### Metrics Exposed

- Number of active recurring links
- Pending executions count
- Success/failure rates
- Average execution time
- Retry statistics

### Logging

All operations are logged with appropriate levels:
- `log` - Successful operations
- `debug` - Detailed execution info
- `warn` - Retries and recoverable errors
- `error` - Critical failures

## Production Considerations

### Security

- Rate limit all API endpoints
- Validate and sanitize all inputs
- Use environment variables for sensitive data
- Implement authentication/authorization (future enhancement)

### Performance

- Database indexes on frequently queried columns
- Pagination for list endpoints
- Batch processing for scheduler
- Connection pooling for Supabase

### Reliability

- Idempotent execution records (prevent double-charging)
- Database transactions for atomic operations
- Row locking to prevent race conditions
- Graceful error handling with retry logic

### Privacy

- Support X-Ray privacy toggle
- Hide amounts/senders when enabled
- Comply with Stellar privacy features

## Future Enhancements

1. **Multi-user Support**: Link recurring payments to specific user accounts
2. **Dynamic Amount Adjustment**: Allow amount changes based on usage
3. **Trial Periods**: Support free trial periods before billing starts
4. **Proration**: Handle mid-cycle upgrades/downgrades
5. **Dunning Management**: Advanced retry strategies for failed payments
6. **Analytics Dashboard**: Revenue tracking and forecasting
7. **Webhook Notifications**: Real-time webhooks for payment events
8. **Custom Schedules**: Support for non-standard frequencies (bi-weekly, quarterly)
9. **Bulk Operations**: Pause/resume multiple links at once
10. **Export Functionality**: CSV/PDF reports of execution history

## Troubleshooting

### Common Issues

**Payments not executing:**
- Check scheduler is running (look for cron logs)
- Verify `next_execution_date` is in the past
- Ensure platform account has sufficient funds
- Check Stellar network connectivity

**Too many retry attempts:**
- Adjust `RECURRING_PAYMENT_MAX_RETRY` environment variable
- Monitor failure reasons in execution logs
- Verify recipient account can receive payments

**Database errors:**
- Check Supabase connection string
- Verify migrations have been applied
- Monitor database connection pool

## Migration Guide

To deploy the recurring payments feature:

1. **Apply Database Migration**
   ```bash
   # Run the migration file
   psql <connection_string> -f supabase/migrations/20250326000000_create_recurring_payments_table.sql
   ```

2. **Update Environment Variables**
   Add recurring payment config to `.env`

3. **Deploy Code**
   Deploy updated backend code with new modules

4. **Verify Scheduler**
   Check logs to confirm scheduler is running

5. **Test Endpoints**
   Create test recurring link and verify execution

## Support

For issues or questions:
- Check implementation plan: `Recurring_Payment_Link_Engine_*.md`
- Review code comments in source files
- Consult Stellar documentation: https://developers.stellar.org
- Contact development team

---

**Version**: 1.0.0  
**Last Updated**: March 26, 2025  
**Branch**: feat/recurring-payments

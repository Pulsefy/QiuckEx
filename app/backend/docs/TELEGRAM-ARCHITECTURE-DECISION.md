# Telegram Integration Architecture Decision Record

## Decision

Telegram notifications use a **separate, parallel system** rather than integrating into the existing `notification_preferences` table structure.

## Rationale

### Why Separate Tables?

1. **Different Data Model**: Telegram requires storing:
   - Telegram user ID (bigint, unique to Telegram platform)
   - Verification codes (temporary, security-sensitive)
   - Telegram username (optional, can change)
   
   These don't fit the generic notification_preferences schema.

2. **Security Requirements**:
   - Verification flow unique to Telegram
   - One-time codes expire after use
   - Different authentication model than email/push/webhook

3. **User Experience**:
   - Interactive bot commands for management
   - Real-time linking flow via chat
   - Self-service settings within Telegram

4. **Operational Simplicity**:
   - Separate logging for audit trail
   - Independent monitoring of Telegram-specific metrics
   - Easier to debug issues in isolation

## How It Works

### Event Flow

```
Event → NotificationService.dispatch()
  ↓
Loads prefs from notification_preferences (email, push, webhook)
  ↓
For each preference → sendToChannel()
  ↓
If channel === 'telegram' → TelegramNotificationProvider.send()
  ↓
Looks up user in telegram_user_mappings by publicKey
  ↓
Validates: isVerified=true, enabled=true, amount >= threshold
  ↓
Sends via TelegramBotService
  ↓
Logs to telegram_notification_log
```

### Key Points

1. **Dispatch happens automatically** - No changes needed to event handlers
2. **Provider does the lookup** - TelegramNotificationProvider queries telegram_user_mappings
3. **Separate validation** - Checks verification status, not just "enabled"
4. **Independent logging** - Uses telegram_notification_log, not notification_log

## Comparison: Integrated vs Separate

### Option A: Integrated (Rejected)
Add telegram_id column to notification_preferences

**Pros:**
- Single source of truth
- Consistent API

**Cons:**
- Schema pollution (nullable telegram_id, verification_code, etc.)
- Complex validation logic
- Harder to extend Telegram-specific features
- Security concerns mixing verification codes with other prefs

### Option B: Separate (Chosen)
Parallel telegram_user_mappings table

**Pros:**
- Clean separation of concerns
- Telegram-specific fields without affecting other channels
- Independent evolution possible
- Better security isolation
- Simpler queries and debugging

**Cons:**
- Two tables to manage
- Need to ensure consistency between tables

## Implementation Details

### User Registration Flow

1. User creates notification preference via API/UI
   - POST /notifications/preferences/:publicKey
   - channel: 'telegram'
   - Creates row in notification_preferences

2. User links Telegram account via bot
   - Starts conversation with @bot
   - Sends public key
   - Receives verification code
   - Creates/updates row in telegram_user_mappings

3. User verifies linkage
   - Enters code in QuickEx app
   - Marks telegram_user_mappings.is_verified = true

4. Notifications flow
   - Both rows must exist and be enabled
   - Dispatch checks notification_preferences
   - Delivery validates telegram_user_mappings

### Future Enhancement: Unified Preference Management

Consider creating a view or unified query layer:

```sql
CREATE VIEW all_notification_channels AS
SELECT 
  public_key,
  channel,
  enabled,
  min_amount_stroops,
  events,
  NULL as telegram_id,
  NULL as verification_code
FROM notification_preferences
UNION ALL
SELECT 
  public_key,
  'telegram' as channel,
  enabled,
  min_amount_stroops,
  NULL as events, -- Telegram supports all events
  telegram_id,
  verification_code
FROM telegram_user_mappings;
```

This would simplify future queries and provide a unified interface.

## Testing Strategy

1. **Unit Tests**: Test TelegramNotificationProvider in isolation
2. **Integration Tests**: Verify end-to-end notification flow
3. **Manual Tests**: Test bot interaction flow
4. **Load Tests**: Ensure Telegram API rate limits are respected

## Monitoring

Track separately from other channels:
- Active Telegram mappings count
- Verification success rate
- Delivery latency (target: < 5 seconds)
- Bot command usage statistics

## Rollback Plan

If issues arise:
1. Set TELEGRAM_BOT_TOKEN to empty string (stops bot)
2. Disable all telegram_user_mappings: `UPDATE telegram_user_mappings SET enabled=false`
3. Remove Telegram provider from NotificationsModule

## Migration Path

If we later decide to integrate more tightly:
1. Create migration script to merge data
2. Add telegram_id as nullable column to notification_preferences
3. Migrate existing telegram_user_mappings data
4. Update application logic gradually
5. Deprecate telegram_user_mappings table

---

**Decision Date**: March 28, 2026  
**Decision Maker**: Development Team  
**Review Date**: After initial production deployment  
**Status**: Implemented

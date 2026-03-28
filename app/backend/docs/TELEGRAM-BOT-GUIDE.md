# Telegram Bot Integration Guide

## Overview

QuickEx now supports real-time notifications via Telegram! Users can link their Telegram accounts to receive instant alerts for:

- 💰 Payments received
- 🔒 Escrow deposits, withdrawals, and refunds
- 🔄 Recurring payment events
- ✅ Username registrations

## Setup Instructions

### 1. Create a Telegram Bot

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` command
3. Follow the prompts to name your bot and choose a username
4. BotFather will give you a **token** (looks like: `1234567890:ABCdefGHIjklMNOpqrsTUVwxyz`)
5. **Save this token securely** - you'll need it for configuration

### 2. Configure Environment Variables

Add the following to your backend's `.env` file:

```bash
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
```

### 3. Run Database Migrations

Apply the new database migration:

```bash
# Using Supabase CLI
supabase db push

# Or manually run the migration file
psql $DATABASE_URL < app/backend/supabase/migrations/20260328000001_create_telegram_bot_tables.sql
```

### 4. Install Dependencies

Install the Telegraf library:

```bash
cd app/backend
npm install telegraf
```

### 5. Restart the Backend

Restart your NestJS backend to load the new Telegram integration:

```bash
npm run dev
```

You should see in the logs:
```
Telegram bot started successfully
```

## User Experience

### Linking Accounts

Users can link their QuickEx account to Telegram by:

1. **Starting a conversation with the bot**
   - Search for your bot on Telegram (use the username you created)
   - Click "Start" or send `/start`

2. **Sending their public key**
   - The bot will prompt for their QuickEx public key
   - User sends their Stellar public key (starts with `G...`)

3. **Verification**
   - The bot generates a verification code
   - User enters this code in the QuickEx app/website
   - Once verified, notifications are enabled!

### Bot Commands

Users can interact with the bot using these commands:

| Command | Description |
|---------|-------------|
| `/start` | Begin linking account or view status |
| `/status` | Check current linkage status |
| `/unlink` | Disconnect Telegram from QuickEx |
| `/settings` | View notification settings |
| `/min <amount>` | Set minimum amount threshold (in XLM) |
| `/enable` | Enable notifications |
| `/disable` | Temporarily disable notifications |
| `/help` | Show help message |
| `/cancel` | Cancel current operation |

### Example Conversation Flow

```
User: /start

Bot: 👋 Welcome to QuickEx Notifications Bot!

     I'll send you real-time alerts for:
     • 💰 Payments received
     • 🔒 Escrow deposits, withdrawals, and refunds

     To link your QuickEx account:
     1. Copy your QuickEx public key (starts with G...)
     2. Send it to me in the next message

     Or use /cancel anytime to abort.

User: GDQERHRWJYV7JHRP5V7DWJVI6Y5ABZP3YRH7DKYJRBEGJQKE6IQEOSY2

Bot: 🔐 Verification Required

     To confirm you own this QuickEx account, please visit:
     `GDQERHRWJYV7JHRP5V7DWJVI6Y5ABZP3YRH7DKYJRBEGJQKE6IQEOSY2`

     And enter this verification code:
     ✨ `A7K9M2` ✨

     Once verified, I'll start sending you notifications!

[User verifies on QuickEx platform]

Bot: ✅ Your account has been verified! You'll now receive 
     real-time notifications for all activity.
```

## API Endpoints

The integration provides REST APIs for programmatic management:

### Check Linkage Status
```http
GET /telegram/status/:telegramId
```

### Verify Account Linkage
```http
POST /telegram/verify/:telegramId
Content-Type: application/json

{
  "verificationCode": "A7K9M2"
}
```

### Update Settings
```http
PUT /telegram/settings/:telegramId
Content-Type: application/json

{
  "enabled": true,
  "minAmountStroops": "10000000"
}
```

### Unlink Account
```http
DELETE /telegram/link/:telegramId
```

## Notification Examples

### Payment Received
```
💰 Payment Received

You received 10.0000000 XLM from GDQERH...

Transaction: `abc123d...`
From: `GDQERHT...`

⏰ 3/28/2026, 10:30:45 AM
```

### Escrow Deposit
```
🔒 Escrow Deposit Confirmed

Your escrow of 50.0000000 XLM has been deposited.

Commitment: `commit123...`

⏰ 3/28/2026, 10:30:45 AM
```

## Configuration Options

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Yes | Bot token from BotFather |

### Default Settings

- **Minimum Amount**: 0 XLM (notifies for all amounts)
- **Enabled**: true (notifications on by default)
- **Events**: All events (payments, escrow, recurring payments)

## Troubleshooting

### Bot doesn't start

**Problem**: Logs show "TELEGRAM_BOT_TOKEN not set"

**Solution**: 
- Verify the environment variable is set correctly
- Check for typos in the token
- Ensure no extra whitespace

### Users can't verify

**Problem**: Verification code doesn't work

**Solution**:
- Codes are case-insensitive
- Check that the user is entering the code in the app, not Telegram
- Verify the database migration was applied successfully

### Notifications not sending

**Problem**: Bot is running but users don't receive notifications

**Solution**:
1. Check user's linkage status: `GET /telegram/status/:telegramId`
2. Verify user is marked as `isVerified: true`
3. Check `enabled: true` in settings
4. Review `telegram_notification_log` table for delivery failures
5. Check bot logs for error messages

### Rate limiting

Telegram has rate limits:
- ~30 messages per second
- Broadcasts: max 100 recipients at once

The integration handles this automatically with retry logic.

## Security Considerations

1. **Token Storage**: Store `TELEGRAM_BOT_TOKEN` securely (use secrets manager)
2. **Verification**: Always require verification codes to prevent unauthorized linking
3. **Privacy**: Don't expose Telegram IDs in public APIs
4. **Unlinking**: Make it easy for users to disconnect at any time

## Testing

### Manual Testing

1. Start the bot in development mode
2. Link your personal Telegram account
3. Trigger test events (send test payment, create escrow)
4. Verify notifications arrive within seconds

### Unit Tests

Run the unit tests:

```bash
npm run test:unit -- telegram
```

### Integration Testing

For end-to-end testing:

```bash
npm run test:int -- telegram
```

## Production Deployment

### Scaling Considerations

- **Single Instance**: Telegraf works best with a single bot instance
- **Redis Session Store**: For multi-instance deployments, configure Redis for sessions
- **Webhook Mode**: For large-scale deployments, consider webhook instead of long polling

### Monitoring

Monitor these metrics:
- Active Telegram mappings count
- Notification delivery success rate
- Average delivery latency
- Failed verification attempts

### Backup & Recovery

- Regular backups of `telegram_user_mappings` table
- Export bot token to secure backup location
- Document recovery procedure for bot token rotation

## Advanced Features

### Custom Message Templates

To customize notification messages, modify the `formatMessageBody()` method in `telegram.provider.ts`.

### Event Filtering

Users can filter which events trigger notifications by updating their preferences via the API.

### Analytics

Track popular features:
- Most common minimum amount settings
- Peak notification times
- User retention after enabling notifications

## Support

For issues or questions:
- Check the bot logs for error messages
- Review the `telegram_notification_log` table
- Test with the provided API endpoints
- Consult the [main README](../README.md) for general setup

## Resources

- [Telegraf Documentation](https://telegraf.js.org/)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [NestJS Modules](https://docs.nestjs.com/modules)

---

**Status**: ✅ Production Ready  
**Version**: 1.0.0  
**Last Updated**: March 28, 2026

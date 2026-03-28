# Telegram Bot - Quick Reference Card

## 🚀 Quick Start (3 minutes)

```bash
# 1. Install dependency
cd app/backend
npm install telegraf

# 2. Add to .env
TELEGRAM_BOT_TOKEN=your-bot-token-here

# 3. Run migration
supabase db push

# 4. Start server
npm run dev
```

## 🤖 Create Bot (2 minutes)

1. Open Telegram → Search `@BotFather`
2. Send `/newbot`
3. Choose name and username
4. **Save the token** you receive

## 📱 User Commands

| Command | Description |
|---------|-------------|
| `/start` | Link account |
| `/status` | Check status |
| `/unlink` | Disconnect |
| `/settings` | View settings |
| `/min 1.5` | Set min (XLM) |
| `/enable` | Turn on alerts |
| `/disable` | Pause alerts |
| `/help` | Show help |

## 🔗 Account Linking Flow

```
User: /start
Bot: "Send your public key (G...)"
User: GDQERH...
Bot: "Verification code: A7K9M2"
[User enters code in app]
Bot: "✅ Verified! Alerts enabled."
```

## 📡 API Endpoints

```http
GET /telegram/status/:telegramId
POST /telegram/verify/:telegramId
PUT /telegram/settings/:telegramId  
DELETE /telegram/link/:telegramId
```

## 🎯 Event Types Notified

- 💰 `payment.received`
- 🔒 `EscrowDeposited`
- 🔓 `EscrowWithdrawn`
- ↩️ `EscrowRefunded`
- ✅ `username.claimed`
- 🔄 `recurring.*` events

## ⚙️ Configuration

```bash
TELEGRAM_BOT_TOKEN=1234567890:ABCdef...  # Required
```

That's it! Bot auto-starts when token is set.

## 🧪 Test It

1. Start bot in Telegram
2. Send `/start`
3. Enter test public key: `GDQERHRWJYV7JHRP5V7DWJVI6Y5ABZP3YRH7DKYJRBEGJQKE6IQEOSY2`
4. Trigger test payment
5. Receive instant alert!

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| Bot doesn't start | Check token in `.env` |
| Can't verify | Code is case-insensitive |
| No notifications | Check user is verified + enabled |
| Rate limit errors | Wait 30s between messages |

## 📊 Monitor

```sql
-- Active users
SELECT COUNT(*) FROM telegram_user_mappings 
WHERE is_verified = true AND enabled = true;

-- Recent deliveries
SELECT * FROM telegram_notification_log 
ORDER BY created_at DESC LIMIT 10;
```

## 📚 Full Docs

- [Complete Setup Guide](../app/backend/docs/TELEGRAM-BOT-GUIDE.md)
- [Implementation Summary](../TELEGRAM_IMPLEMENTATION_SUMMARY.md)

---

**Status**: ✅ Production Ready  
**Version**: 1.0.0  
**Support**: Check logs for error details

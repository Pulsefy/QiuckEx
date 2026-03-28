/**
 * Telegram Bot Integration Module
 * 
 * Provides real-time notifications via Telegram bot.
 * 
 * Features:
 * - User account pairing via verification codes
 * - Real-time payment and escrow notifications
 * - Configurable notification settings (min amount, enable/disable)
 * - Idempotent delivery with retry logic
 * - Rate limiting and error handling
 * 
 * @module TelegramModule
 */

export { TelegramBotService } from './telegram-bot.service';
export { TelegramRepository } from './telegram.repository';
export { TelegramNotificationProvider } from './telegram.provider';
export { TelegramController } from './telegram.controller';

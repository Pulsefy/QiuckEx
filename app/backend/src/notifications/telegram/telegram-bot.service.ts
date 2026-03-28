import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from "@nestjs/common";
import { Context, Telegraf } from "telegraf";
import { message } from "telegraf/filters";
import { TelegramRepository } from "./telegram.repository";

interface ExtendedContext extends Context {
  session?: {
    linkingPublicKey?: string;
    verificationCode?: string;
  };
}

@Injectable()
export class TelegramBotService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(TelegramBotService.name);
  private bot: Telegraf<ExtendedContext> | null = null;

  constructor(private readonly telegramRepo: TelegramRepository) {}

  async onModuleInit(): Promise<void> {
    const telegramToken = process.env["TELEGRAM_BOT_TOKEN"];

    if (!telegramToken) {
      this.logger.warn(
        "TELEGRAM_BOT_TOKEN not set - Telegram bot will not be initialized",
      );
      return;
    }

    try {
      this.bot = new Telegraf<ExtendedContext>(telegramToken);

      // Register command handlers
      this.registerCommands();

      // Start the bot
      await this.bot.launch();
      this.logger.log("Telegram bot started successfully");

      // Enable graceful stop
      process.once("SIGINT", () => this.bot?.stop("SIGINT"));
      process.once("SIGTERM", () => this.bot?.stop("SIGTERM"));
    } catch (error) {
      this.logger.error(
        `Failed to start Telegram bot: ${(error as Error).message}`,
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.bot) {
      await this.bot.stop();
      this.logger.log("Telegram bot stopped");
    }
  }

  /**
   * Register all bot command handlers
   */
  private registerCommands(): void {
    if (!this.bot) return;

    // /start command - Welcome and instructions
    this.bot.start(async (ctx) => {
      const telegramId = ctx.from?.id;

      if (!telegramId) {
        await ctx.reply("⚠️ Unable to identify you. Please try again.");
        return;
      }

      // Check if user is already linked
      const existingMapping = await this.telegramRepo.findByTelegramId(
        telegramId,
      );

      if (existingMapping) {
        await ctx.reply(
          `✅ Your Telegram account is already linked to QuickEx!\n\n` +
            `Public Key: \`${existingMapping.publicKey}\`\n\n` +
            `You will receive real-time notifications for:\n` +
            `• Payment received\n` +
            `• Escrow status changes\n\n` +
            `Use /unlink to disconnect your account.`,
          { parse_mode: "Markdown" },
        );
        return;
      }

      // Show welcome message with instructions
      await ctx.reply(
        `👋 Welcome to QuickEx Notifications Bot!\n\n` +
          `I'll send you real-time alerts for:\n` +
          `• 💰 Payments received\n` +
          `• 🔒 Escrow deposits, withdrawals, and refunds\n\n` +
          `To link your QuickEx account:\n` +
          `1. Copy your QuickEx public key (starts with G...)\n` +
          `2. Send it to me in the next message\n\n` +
          `Or use /cancel anytime to abort.`,
        { parse_mode: "Markdown" },
      );

      // Set session state for linking
      if (!ctx.session) ctx.session = {};
      ctx.session.linkingPublicKey = undefined;
    });

    // Handle public key submission for linking
    this.bot.on(message("text"), async (ctx) => {
      const telegramId = ctx.from?.id;
      const text = ctx.message.text.trim();

      if (!telegramId) return;

      // Check if user is in linking flow
      if (!ctx.session) ctx.session = {};

      // Handle cancellation
      if (text.toLowerCase() === "/cancel") {
        ctx.session.linkingPublicKey = undefined;
        await ctx.reply("❌ Linking process cancelled.");
        return;
      }

      // If no active linking session, ignore
      if (!ctx.session.linkingPublicKey && !text.startsWith("G")) {
        return;
      }

      // Validate Stellar public key format
      if (!text.startsWith("G") || text.length !== 56) {
        await ctx.reply(
          "⚠️ That doesn't look like a valid Stellar public key.\n\n" +
            "Please send a key that starts with 'G' and is 56 characters long.\n\n" +
            "Or use /cancel to abort.",
        );
        return;
      }

      // Store the public key and ask for verification
      if (!ctx.session.linkingPublicKey) {
        ctx.session.linkingPublicKey = text;

        // Generate verification code
        const verificationCode = Math.random().toString(36).substring(2, 8).toUpperCase();
        ctx.session.verificationCode = verificationCode;

        // Save mapping with verification code
        await this.telegramRepo.upsertMapping({
          telegramId,
          username: ctx.from?.username ?? undefined,
          publicKey: text,
          verificationCode,
        });

        await ctx.reply(
          `🔐 Verification Required\n\n` +
            `To confirm you own this QuickEx account, please visit:\n` +
            `\`${text}\`\n\n` +
            `And enter this verification code:\n` +
            `✨ \`${verificationCode}\` ✨\n\n` +
            `Once verified, I'll start sending you notifications!`,
          { parse_mode: "Markdown" },
        );
        return;
      }
    });

    // /status command - Show current linkage status
    this.bot.command("status", async (ctx) => {
      const telegramId = ctx.from?.id;
      if (!telegramId) return;

      const mapping = await this.telegramRepo.findByTelegramId(telegramId);

      if (!mapping) {
        await ctx.reply(
          "❌ Your Telegram account is not linked to any QuickEx account.\n\n" +
            "Use /start to begin linking.",
        );
        return;
      }

      const status = mapping.isVerified ? "✅ Verified" : "⏳ Pending verification";
      const notifications = mapping.enabled ? "🔔 Enabled" : "🔕 Disabled";

      await ctx.reply(
        `📊 Your QuickEx Link Status\n\n` +
          `Public Key: \`${mapping.publicKey}\`\n` +
          `Status: ${status}\n` +
          `Notifications: ${notifications}\n` +
          `Min Amount: ${Number(mapping.minAmountStroops) / 10_000_000} XLM\n\n` +
          `Use:\n` +
          `/unlink - Disconnect account\n` +
          `/settings - Change notification settings`,
        { parse_mode: "Markdown" },
      );
    });

    // /unlink command - Remove linkage
    this.bot.command("unlink", async (ctx) => {
      const telegramId = ctx.from?.id;
      if (!telegramId) return;

      const mapping = await this.telegramRepo.findByTelegramId(telegramId);

      if (!mapping) {
        await ctx.reply("❌ No QuickEx account is linked.");
        return;
      }

      await this.telegramRepo.deleteMapping(telegramId);

      if (!ctx.session) ctx.session = {};
      ctx.session.linkingPublicKey = undefined;

      await ctx.reply(
        "✅ Your QuickEx account has been disconnected.\n\n" +
          "You will no longer receive notifications here.\n" +
          "Use /start to link again anytime.",
      );
    });

    // /settings command - Configure notification preferences
    this.bot.command("settings", async (ctx) => {
      const telegramId = ctx.from?.id;
      if (!telegramId) return;

      const mapping = await this.telegramRepo.findByTelegramId(telegramId);

      if (!mapping) {
        await ctx.reply("❌ No QuickEx account linked. Use /start first.");
        return;
      }

      await ctx.reply(
        `⚙️ Notification Settings\n\n` +
          `Current minimum amount: ${Number(mapping.minAmountStroops) / 10_000_000} XLM\n\n` +
          `To change the minimum amount, send:\n` +
          `/min 1.5 (for 1.5 XLM)\n\n` +
          `To toggle notifications:\n` +
          `/enable - Turn on notifications\n` +
          `/disable - Turn off notifications`,
        { parse_mode: "Markdown" },
      );
    });

    // /min command - Set minimum amount threshold
    this.bot.command("min", async (ctx) => {
      const telegramId = ctx.from?.id;
      if (!telegramId) return;

      const mapping = await this.telegramRepo.findByTelegramId(telegramId);
      if (!mapping) {
        await ctx.reply("❌ No QuickEx account linked. Use /start first.");
        return;
      }

      const args = ctx.message.text.split(" ");
      if (args.length < 2) {
        await ctx.reply("Usage: /min <amount_in_XLM>\nExample: /min 1.5");
        return;
      }

      const xlmAmount = parseFloat(args[1]);
      if (isNaN(xlmAmount) || xlmAmount < 0) {
        await ctx.reply("❌ Invalid amount. Please provide a positive number.");
        return;
      }

      const stroops = BigInt(Math.round(xlmAmount * 10_000_000));
      await this.telegramRepo.setMinAmount(telegramId, stroops);

      await ctx.reply(
        `✅ Minimum amount updated to \`${xlmAmount} XLM\`\n\n` +
          `You'll only receive notifications for payments >= this amount.`,
        { parse_mode: "Markdown" },
      );
    });

    // /enable command - Enable notifications
    this.bot.command("enable", async (ctx) => {
      const telegramId = ctx.from?.id;
      if (!telegramId) return;

      const mapping = await this.telegramRepo.findByTelegramId(telegramId);
      if (!mapping) {
        await ctx.reply("❌ No QuickEx account linked. Use /start first.");
        return;
      }

      await this.telegramRepo.setEnabled(telegramId, true);
      await ctx.reply("✅ Notifications enabled! You'll now receive real-time alerts.");
    });

    // /disable command - Disable notifications temporarily
    this.bot.command("disable", async (ctx) => {
      const telegramId = ctx.from?.id;
      if (!telegramId) return;

      const mapping = await this.telegramRepo.findByTelegramId(telegramId);
      if (!mapping) {
        await ctx.reply("❌ No QuickEx account linked. Use /start first.");
        return;
      }

      await this.telegramRepo.setEnabled(telegramId, false);
      await ctx.reply("🔕 Notifications disabled. Use /enable to turn them back on.");
    });

    // /help command
    this.bot.command("help", async (ctx) => {
      await ctx.reply(
        `📖 QuickEx Bot Commands\n\n` +
          `/start - Link your QuickEx account\n` +
          `/status - Check linkage status\n` +
          `/unlink - Disconnect account\n` +
          `/settings - Notification settings\n` +
          `/min <amount> - Set minimum amount (in XLM)\n` +
          `/enable - Enable notifications\n` +
          `/disable - Disable notifications\n` +
          `/help - Show this help message\n` +
          `/cancel - Cancel current operation`,
        { parse_mode: "Markdown" },
      );
    });
  }

  /**
   * Send a notification message to a Telegram user
   */
  async sendNotification(
    telegramId: number,
    title: string,
    body: string,
    metadata?: Record<string, unknown>,
  ): Promise<number | null> {
    if (!this.bot) {
      throw new Error("Telegram bot not initialized");
    }

    try {
      // Format message with emoji based on event type
      const emoji = this.getEmojiForEvent(metadata?.eventType as string);
      const formattedMessage = `${emoji} *${title}*\n\n${body}`;

      const result = await this.bot.telegram.sendMessage(telegramId, formattedMessage, {
        parse_mode: "Markdown",
      });

      return result.message_id;
    } catch (error) {
      this.logger.error(
        `Failed to send Telegram notification to ${telegramId}: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  /**
   * Get emoji for different event types
   */
  private getEmojiForEvent(eventType?: string): string {
    if (!eventType) return "🔔";

    const emojiMap: Record<string, string> = {
      "payment.received": "💰",
      "EscrowDeposited": "🔒",
      "EscrowWithdrawn": "🔓",
      "EscrowRefunded": "↩️",
      "username.claimed": "✅",
      "recurring.payment.executed": "🔄",
      "recurring.payment.failed": "❌",
      "recurring.payment.due": "⏰",
    };

    return emojiMap[eventType] || "🔔";
  }

  /**
   * Verify a user with the verification code
   */
  async verifyUser(telegramId: number, verificationCode: string): Promise<boolean> {
    const mapping = await this.telegramRepo.findByTelegramId(telegramId);

    if (!mapping || !mapping.verificationCode) {
      return false;
    }

    if (mapping.verificationCode.toUpperCase() === verificationCode.toUpperCase()) {
      await this.telegramRepo.markAsVerified(telegramId);
      return true;
    }

    return false;
  }

  /**
   * Get the bot instance (for advanced usage)
   */
  getBot(): Telegraf<ExtendedContext> | null {
    return this.bot;
  }
}
import {
  Controller,
  Get,
  Post,
  Put,  // Added Put import
  Delete,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  Logger,
  BadRequestException,
  NotFoundException,
} from "@nestjs/common";
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from "@nestjs/swagger";
import { TelegramRepository } from "./telegram.repository";
import { TelegramBotService } from "./telegram-bot.service";

/**
 * DTO for verifying Telegram account linkage
 */
class VerifyTelegramLinkDto {
  verificationCode: string;
}

/**
 * DTO for updating Telegram notification settings
 */
class UpdateTelegramSettingsDto {
  enabled?: boolean;
  minAmountStroops?: string;
}

/**
 * Response DTO for Telegram link status
 */
class TelegramLinkStatusResponse {
  isLinked: boolean;
  isVerified: boolean;
  publicKey?: string;
  enabled?: boolean;
  minAmountXlm?: number;
  createdAt?: Date;
}

/**
 * REST API for managing Telegram account linkage and notifications.
 * 
 * Users can:
 * - Link their Telegram account to a QuickEx public key
 * - Verify the linkage with a code
 * - Update notification settings
 * - Unlink their account
 */
@ApiTags("Telegram")
@Controller("telegram")
export class TelegramController {
  private readonly logger = new Logger(TelegramController.name);

  constructor(
    private readonly telegramRepo: TelegramRepository,
    private readonly telegramBot: TelegramBotService,
  ) {}

  /**
   * GET /telegram/status/:telegramId
   * Check if a Telegram account is linked to QuickEx
   */
  @Get("status/:telegramId")
  @ApiOperation({ summary: "Check Telegram account linkage status" })
  @ApiParam({ name: "telegramId", description: "Telegram user ID" })
  @ApiResponse({
    status: 200,
    type: TelegramLinkStatusResponse,
    description: "Linkage status retrieved successfully",
  })
  async getStatus(
    @Param("telegramId") telegramId: string,
  ): Promise<TelegramLinkStatusResponse> {
    const tid = Number(telegramId);
    if (isNaN(tid)) {
      throw new BadRequestException("Invalid Telegram ID");
    }

    const mapping = await this.telegramRepo.findByTelegramId(tid);

    if (!mapping) {
      return {
        isLinked: false,
        isVerified: false,
      };
    }

    return {
      isLinked: true,
      isVerified: mapping.isVerified,
      publicKey: mapping.publicKey,
      enabled: mapping.enabled,
      minAmountXlm: Number(mapping.minAmountStroops) / 10_000_000,
      createdAt: mapping.createdAt,
    };
  }

  /**
   * POST /telegram/verify/:telegramId
   * Verify a Telegram account linkage with the verification code
   */
  @Post("verify/:telegramId")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Verify Telegram account linkage" })
  @ApiParam({ name: "telegramId", description: "Telegram user ID" })
  @ApiResponse({ status: 200, description: "Verification successful" })
  @ApiResponse({ status: 400, description: "Invalid verification code" })
  async verifyLink(
    @Param("telegramId") telegramId: string,
    @Body() dto: VerifyTelegramLinkDto,
  ): Promise<{ success: boolean }> {
    const tid = Number(telegramId);
    if (isNaN(tid)) {
      throw new BadRequestException("Invalid Telegram ID");
    }

    const mapping = await this.telegramRepo.findByTelegramId(tid);

    if (!mapping) {
      throw new NotFoundException("No pending linkage found");
    }

    if (mapping.isVerified) {
      return { success: true };
    }

    const isValid = await this.telegramBot.verifyUser(tid, dto.verificationCode);

    if (!isValid) {
      throw new BadRequestException("Invalid verification code");
    }

    this.logger.log(`Telegram account ${tid} verified successfully`);

    return { success: true };
  }

  /**
   * PUT /telegram/settings/:telegramId
   * Update Telegram notification settings
   */
  @Put("settings/:telegramId")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Update Telegram notification settings" })
  @ApiParam({ name: "telegramId", description: "Telegram user ID" })
  @ApiResponse({ status: 200, description: "Settings updated successfully" })
  async updateSettings(
    @Param("telegramId") telegramId: string,
    @Body() dto: UpdateTelegramSettingsDto,
  ): Promise<{ success: boolean }> {
    const tid = Number(telegramId);
    if (isNaN(tid)) {
      throw new BadRequestException("Invalid Telegram ID");
    }

    const mapping = await this.telegramRepo.findByTelegramId(tid);

    if (!mapping) {
      throw new NotFoundException("Telegram account not linked");
    }

    if (!mapping.isVerified) {
      throw new BadRequestException("Telegram account not verified");
    }

    // Update enabled status if provided
    if (dto.enabled !== undefined) {
      await this.telegramRepo.setEnabled(tid, dto.enabled);
    }

    // Update minimum amount if provided
    if (dto.minAmountStroops !== undefined) {
      const stroops = BigInt(dto.minAmountStroops);
      if (stroops < 0n) {
        throw new BadRequestException("Minimum amount cannot be negative");
      }
      await this.telegramRepo.setMinAmount(tid, stroops);
    }

    this.logger.log(`Telegram settings updated for ${tid}`);

    return { success: true };
  }

  /**
   * DELETE /telegram/link/:telegramId
   * Unlink a Telegram account from QuickEx
   */
  @Delete("link/:telegramId")
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Unlink Telegram account" })
  @ApiParam({ name: "telegramId", description: "Telegram user ID" })
  @ApiResponse({ status: 204, description: "Account unlinked successfully" })
  async unlinkAccount(
    @Param("telegramId") telegramId: string,
  ): Promise<void> {
    const tid = Number(telegramId);
    if (isNaN(tid)) {
      throw new BadRequestException("Invalid Telegram ID");
    }

    const mapping = await this.telegramRepo.findByTelegramId(tid);

    if (!mapping) {
      throw new NotFoundException("Telegram account not linked");
    }

    await this.telegramRepo.deleteMapping(tid);

    this.logger.log(`Telegram account ${tid} unlinked successfully`);
  }
}
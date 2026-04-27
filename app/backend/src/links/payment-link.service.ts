import { Injectable, Logger, NotFoundException } from "@nestjs/common";
import { LinkState } from "../links/link-state-machine";
import { PaymentLinkStatusDto } from "../dto/link/payment-link-status.dto";
import { HorizonService } from "../transactions/horizon.service";
import { SupabaseService } from "../supabase/supabase.service";
import { LinksService } from "../links/links.service";
import { PathPreviewService } from "../stellar/path-preview.service";

import { LinkMetadataResponseDto } from "../dto/link/link-metadata-response.dto";

@Injectable()
export class PaymentLinkService {
  private readonly logger = new Logger(PaymentLinkService.name);
  private readonly DEFAULT_EXPIRY_DAYS = 30;

  constructor(
    private readonly horizonService: HorizonService,
    private readonly supabaseService: SupabaseService,
    private readonly linksService: LinksService,
    private readonly pathPreviewService?: PathPreviewService,
  ) {}

  /**
   * Get the current state of a payment link
   * Payment links are stateless URLs, so we determine state by:
   * 1. Checking if the username exists
   * 2. Checking if a matching payment has been made
   * 3. Checking if the link has expired
   */
  async getPaymentLinkStatus(params: {
    username: string;
    amount: number;
    asset?: string;
    memo?: string;
    acceptedAssets?: string[];
  }): Promise<PaymentLinkStatusDto> {
    const { username, amount, asset = "XLM", memo, acceptedAssets } = params;

    // 1. Get username record to find destination public key
    const usernameRecord = await this.getUsernameRecord(username);
    const destinationPublicKey = usernameRecord.public_key;

    // 2. Generate metadata to get canonical format and swap options
    const metadata = await this.linksService.generateMetadata({
      amount,
      asset,
      username,
      memo,
      acceptedAssets,
      expirationDays: this.DEFAULT_EXPIRY_DAYS,
    });

    // 3. Check if payment has been made
    const paymentInfo = await this.checkIfPaymentMade(
      destinationPublicKey,
      metadata.amount,
      metadata.asset,
      metadata.memo,
    );

    // 4. Determine link state
    const state = this.determineLinkState(metadata, paymentInfo);

    // 5. Build swap options if acceptedAssets provided
    const swapOptions = metadata.swapOptions || null;

    // 6. Build user-friendly message and available actions
    const { userMessage, availableActions } = this.buildUserContext(state);

    return {
      state,
      username: metadata.username || username,
      amount: metadata.amount,
      asset: metadata.asset,
      memo: metadata.memo,
      destinationPublicKey,
      expiresAt: metadata.expiresAt,
      transactionHash: paymentInfo?.transactionHash || null,
      paidAt: paymentInfo?.paidAt || null,
      swapOptions,
      acceptsMultipleAssets: !!acceptedAssets && acceptedAssets.length > 0,
      acceptedAssets: metadata.acceptedAssets || null,
      userMessage,
      availableActions,
    };
  }

  /**
   * Get username record from database
   */
  private async getUsernameRecord(
    username: string,
  ): Promise<{ public_key: string }> {
    const { data, error } = await this.supabaseService
      .getClient()
      .from("usernames")
      .select("public_key")
      .eq("username", username.toLowerCase())
      .single();

    if (error || !data) {
      throw new NotFoundException(`Username '${username}' not found`);
    }

    return data;
  }

  /**
   * Check if a matching payment has been made on-chain
   * Looks for recent payments to the destination with matching amount and memo
   */
  private async checkIfPaymentMade(
    destinationPublicKey: string,
    amount: string,
    asset: string,
    memo: string | null,
  ): Promise<{ transactionHash: string; paidAt: Date } | null> {
    try {
      // Get recent payments to this account
      const payments = await this.horizonService.getPayments(
        destinationPublicKey,
        undefined,
        50, // Check last 50 payments
      );

      // Find a matching payment
      const matchingPayment = payments.items.find((payment) => {
        // Check amount (allow small floating point differences)
        const paymentAmount = parseFloat(payment.amount);
        const expectedAmount = parseFloat(amount);
        const amountMatches =
          Math.abs(paymentAmount - expectedAmount) < 0.0000001;

        // Check asset
        const assetMatches = payment.asset === asset;

        // Check memo if provided
        const memoMatches = !memo || payment.memo === memo;

        return amountMatches && assetMatches && memoMatches;
      });

      if (matchingPayment) {
        return {
          transactionHash: matchingPayment.txHash,
          paidAt: new Date(matchingPayment.timestamp),
        };
      }

      return null;
    } catch (error) {
      this.logger.error(`Failed to check payment status: ${error}`);
      // If we can't check Horizon, assume payment not made
      return null;
    }
  }

  /**
   * Determine the current state of the payment link
   */
  private determineLinkState(
    metadata: LinkMetadataResponseDto,
    paymentInfo: { transactionHash: string; paidAt: Date } | null,
  ): LinkState {
    // If payment has been made, link is PAID
    if (paymentInfo) {
      return LinkState.PAID;
    }

    // Check if link has expired
    if (metadata.expiresAt && new Date(metadata.expiresAt) < new Date()) {
      return LinkState.EXPIRED;
    }

    // Otherwise, link is ACTIVE
    return LinkState.ACTIVE;
  }

  /**
   * Build user-friendly message and available actions based on state
   */
  private buildUserContext(state: LinkState): {
    userMessage: string;
    availableActions: string[];
  } {
    switch (state) {
      case LinkState.ACTIVE:
        return {
          userMessage:
            "This payment link is active and ready to receive payment",
          availableActions: ["pay", "share"],
        };

      case LinkState.EXPIRED:
        return {
          userMessage:
            "This payment link has expired. Please request a new payment link.",
          availableActions: [],
        };

      case LinkState.PAID:
        return {
          userMessage: "Payment completed successfully!",
          availableActions: ["view_transaction"],
        };

      case LinkState.REFUNDED:
        return {
          userMessage: "This payment has been refunded.",
          availableActions: [],
        };

      default:
        return {
          userMessage: "Unknown payment link state",
          availableActions: [],
        };
    }
  }
}

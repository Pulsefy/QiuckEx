import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';

@Injectable()
export class NotificationService {
  private readonly logger = new Logger('NotificationHook');

  // Handles the username event
  @OnEvent('username.claimed', { async: true })
  handleUsernameClaimed(payload: { username: string; publicKey: string }) {
    this.logger.log(`[Stub] Intent: Notify via Telegram for New Username`);
    this.logger.debug(`Payload Shape: username=${payload.username}, pk=${payload.publicKey}`);
  }

  // Handles the payment event
  @OnEvent('payment.received', { async: true })
  handlePaymentReceived(payload: { txHash: string; amount: string }) {
    this.logger.log(`[Stub] Intent: Notify via Email for Payment`);
    this.logger.debug(`Payload Shape: txHash=${payload.txHash}, amount=${payload.amount}`);
  }
}
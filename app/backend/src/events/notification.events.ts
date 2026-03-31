export enum NotificationEvent {
  PaymentReceived = 'payment.received',
  UsernameClaimed = 'username.claimed',
  RecurringLinkCreated = 'recurring.link.created',
  RecurringLinkUpdated = 'recurring.link.updated',
  RecurringLinkPaused = 'recurring.link.paused',
  RecurringLinkResumed = 'recurring.link.resumed',
  RecurringLinkCancelled = 'recurring.link.cancelled',
  RecurringLinkCompleted = 'recurring.link.completed',
  RecurringPaymentExecuted = 'recurring.payment.executed',
  RecurringPaymentFailed = 'recurring.payment.failed',
}

export class PaymentReceivedEvent {
  constructor(
    public readonly txHash: string,
    public readonly amount: string,
    public readonly sender: string,
  public readonly recipientPublicKey: string,
  ) {}
}

export class RecurringLinkCreatedEvent {
  constructor(
    public readonly linkId: string,
    public readonly username?: string,
    public readonly destination?: string,
  ) {}
}

export class RecurringLinkUpdatedEvent {
  constructor(
    public readonly linkId: string,
    public readonly changes: Record<string, unknown>,
  ) {}
}

export class RecurringLinkPausedEvent {
  constructor(
    public readonly linkId: string,
    public readonly username?: string,
    public readonly destination?: string,
  ) {}
}

export class RecurringLinkResumedEvent {
  constructor(
    public readonly linkId: string,
    public readonly username?: string,
    public readonly destination?: string,
  ) {}
}

export class RecurringLinkCancelledEvent {
  constructor(
    public readonly linkId: string,
    public readonly username?: string,
    public readonly destination?: string,
  ) {}
}

export class RecurringLinkCompletedEvent {
  constructor(
    public readonly linkId: string,
    public readonly totalExecuted: number,
  ) {}
}

export class RecurringPaymentExecutedEvent {
  constructor(
    public readonly executionId: string,
    public readonly transactionHash: string,
  ) {}
}

export class RecurringPaymentFailedEvent {
  constructor(
    public readonly executionId: string,
    public readonly failureReason: string,
    public readonly permanent: boolean,
  ) {}
}

export class UsernameClaimedEvent {
  constructor(
    public readonly username: string,
    public readonly publicKey: string,
  ) {}
}
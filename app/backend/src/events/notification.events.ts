export enum NotificationEvent {
  PaymentReceived = 'payment.received',
  PaymentLinkExpired = 'payment.link.expired',
  UsernameClaimed = 'username.claimed',
  RecurringLinkCreated = 'recurring.link.created',
  RecurringLinkUpdated = 'recurring.link.updated',
  RecurringLinkPaused = 'recurring.link.paused',
  RecurringLinkResumed = 'recurring.link.resumed',
  RecurringLinkCancelled = 'recurring.link.cancelled',
  RecurringLinkCompleted = 'recurring.link.completed',
  RecurringPaymentExecuted = 'recurring.payment.executed',
  RecurringPaymentFailed = 'recurring.payment.failed',

  // ── SEP-24 fiat-ramp lifecycle events ─────────────────────────────────────
  /** Emitted when an anchor transaction reaches a terminal state. */
  Sep24TransactionTerminal = 'sep24.transaction.terminal',
  /** Emitted when a completed SEP-24 transaction is matched on-chain. */
  Sep24TransactionReconciled = 'sep24.transaction.reconciled',
  /** Emitted when a transaction is stuck past the configured threshold. */
  Sep24TransactionStuck = 'sep24.transaction.stuck',
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

export class AutoReconciliationSucceededEvent {
  constructor(
    public readonly linkId: string,
    public readonly ownerPublicKey: string,
    public readonly txHash: string,
    public readonly amount: string,
    public readonly assetCode: string,
    public readonly confidence: number,
    public readonly matchedAt: string,
  ) {}
}

// ── SEP-24 event classes ───────────────────────────────────────────────────────

/**
 * Emitted when a SEP-24 anchor transaction reaches a terminal state
 * (completed, refunded, expired, or error).
 *
 * Listeners (e.g. NotificationService) use this to dispatch in-app and push
 * notifications to the initiating user.
 */
export class Sep24TransactionTerminalEvent {
  constructor(
    /** Internal UUID of the sep24_transactions row. */
    public readonly transactionId: string,
    /** Anchor-assigned transaction ID. */
    public readonly anchorTransactionId: string,
    /** Anchor domain (e.g. "moneygram.stellar.org"). */
    public readonly anchorDomain: string,
    /** Whether this was a deposit or withdrawal. */
    public readonly type: 'deposit' | 'withdrawal',
    /** Raw anchor status that triggered the terminal transition. */
    public readonly anchorStatus: string,
    /** Resolved internal status. */
    public readonly internalStatus: string,
    /** On-chain Stellar tx hash, if available. */
    public readonly stellarTxHash: string | null,
    /** Amount as a decimal string. */
    public readonly amount: string,
    /** Asset code (e.g. "USDC"). */
    public readonly assetCode: string,
    /** Stellar account of the user who initiated the flow. */
    public readonly userAccount: string,
  ) {}
}

/**
 * Emitted when a completed SEP-24 transaction is verified on-chain and
 * surfaced to the reconciliation module.
 */
export class Sep24TransactionReconciledEvent {
  constructor(
    public readonly transactionId: string,
    public readonly anchorTransactionId: string,
    public readonly anchorDomain: string,
    public readonly type: 'deposit' | 'withdrawal',
    public readonly stellarTxHash: string,
    public readonly amount: string,
    public readonly assetCode: string,
    public readonly userAccount: string,
    public readonly reconciledAt: string,
  ) {}
}

/**
 * Emitted when a SEP-24 transaction is detected as stuck — pending longer
 * than the configured `SEP24_STUCK_THRESHOLD_MS` without reaching a terminal
 * state.
 *
 * Operator tooling listens for this event and surfaces it for manual review.
 */
export class Sep24TransactionStuckEvent {
  constructor(
    public readonly transactionId: string,
    public readonly anchorTransactionId: string,
    public readonly anchorDomain: string,
    public readonly type: 'deposit' | 'withdrawal',
    public readonly amount: string,
    public readonly assetCode: string,
    public readonly userAccount: string,
    public readonly reason: string,
  ) {}
}

export class ReconciliationDriftDetectedEvent {
  constructor(
    public readonly runId: string,
    public readonly countDiscrepancy: number,
    public readonly amountDiscrepancy: string,
    public readonly details: string,
    public readonly occurredAt: string,
  ) {}
}

export class ReconciliationFailedEvent {
  constructor(
    public readonly type: 'failure' | 'skip',
    public readonly consecutiveCount: number,
    public readonly lastReason: string,
    public readonly occurredAt: string,
  ) {}
}
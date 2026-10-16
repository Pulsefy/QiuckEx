import { AnalyticsEventDefinition, AnalyticsFieldType } from './analytics-event-schema.types';

/**
 * Canonical versioned schema registry for QuickEx analytics events.
 *
 * Rules enforced by the compatibility & CI gate (`analytics-schema-compatibility.ts`):
 * - Every analytics event has a versioned schema (`version >= 1`).
 * - Each schema defines `fields` (`Record<string, { type, required, description, enumValues? }>`)
 *   and `requiredFields` (derived or explicit).
 * - Adding a required field or removing any field from an existing event schema
 *   is a breaking change and MUST increment `version` compared to the baseline snapshot,
 *   otherwise CI fails.
 * - Changing a field's type or narrowing its allowed enum values is also a breaking change
 *   requiring a version increment.
 */
export const ANALYTICS_EVENT_SCHEMAS: Readonly<Record<string, AnalyticsEventDefinition>> = {
  'payment.initiated': {
    eventName: 'payment.initiated',
    version: 1,
    category: 'payment',
    description: 'Emitted when a user or merchant initiates a payment flow.',
    fields: {
      paymentId: {
        type: 'string',
        required: true,
        description: 'Unique identifier for the payment attempt.',
      },
      asset: {
        type: 'string',
        required: true,
        description: 'Stellar asset code (e.g. XLM, USDC).',
      },
      amount: {
        type: 'number',
        required: true,
        description: 'Payment amount in asset units.',
      },
      amountUsd: {
        type: 'number',
        required: false,
        description: 'Estimated USD equivalent at initiation time.',
      },
      organizationId: {
        type: 'string',
        required: false,
        description: 'Optional organization scope identifier.',
      },
    },
  },
  'payment.completed': {
    eventName: 'payment.completed',
    version: 1,
    category: 'payment',
    description: 'Emitted when a payment settles on-chain and is confirmed.',
    fields: {
      paymentId: {
        type: 'string',
        required: true,
        description: 'Unique identifier for the completed payment.',
      },
      txHash: {
        type: 'string',
        required: true,
        description: 'On-chain Stellar transaction hash.',
      },
      asset: {
        type: 'string',
        required: true,
        description: 'Stellar asset code (e.g. XLM, USDC).',
      },
      amount: {
        type: 'number',
        required: true,
        description: 'Settled payment amount in asset units.',
      },
      amountUsd: {
        type: 'number',
        required: true,
        description: 'Settled USD value recorded for dashboard reporting.',
      },
      settlementLatencyMs: {
        type: 'number',
        required: false,
        description: 'Elapsed time in milliseconds from initiation to settlement.',
      },
      organizationId: {
        type: 'string',
        required: false,
        description: 'Optional organization scope identifier.',
      },
    },
  },
  'payment.failed': {
    eventName: 'payment.failed',
    version: 1,
    category: 'payment',
    description: 'Emitted when a payment attempt fails or is rejected.',
    fields: {
      paymentId: {
        type: 'string',
        required: true,
        description: 'Unique identifier for the failed payment attempt.',
      },
      asset: {
        type: 'string',
        required: true,
        description: 'Stellar asset code.',
      },
      amount: {
        type: 'number',
        required: true,
        description: 'Attempted payment amount.',
      },
      reasonCode: {
        type: 'string',
        required: true,
        description: 'Standardized failure reason code.',
      },
      organizationId: {
        type: 'string',
        required: false,
        description: 'Optional organization scope identifier.',
      },
    },
  },
  'link.created': {
    eventName: 'link.created',
    version: 1,
    category: 'link',
    description: 'Emitted when a one-time or recurring payment link is created.',
    fields: {
      linkId: {
        type: 'string',
        required: true,
        description: 'Unique identifier of the payment link.',
      },
      linkType: {
        type: 'string',
        required: true,
        description: 'Type of link created.',
        enumValues: ['one_time', 'recurring', 'open_amount'],
      },
      asset: {
        type: 'string',
        required: true,
        description: 'Requested asset code.',
      },
      isPrivate: {
        type: 'boolean',
        required: true,
        description: 'Whether privacy/stealth mode was enabled on the link.',
      },
      organizationId: {
        type: 'string',
        required: false,
        description: 'Optional organization scope identifier.',
      },
    },
  },
  'refund.requested': {
    eventName: 'refund.requested',
    version: 1,
    category: 'refund',
    description: 'Emitted when a refund is requested for a payment.',
    fields: {
      refundId: {
        type: 'string',
        required: true,
        description: 'Unique identifier of the refund attempt.',
      },
      paymentId: {
        type: 'string',
        required: true,
        description: 'Identifier of the original payment.',
      },
      amountUsd: {
        type: 'number',
        required: true,
        description: 'Refund amount in USD.',
      },
      reason: {
        type: 'string',
        required: false,
        description: 'Optional refund reason category.',
      },
    },
  },
  'escrow.lifecycle': {
    eventName: 'escrow.lifecycle',
    version: 1,
    category: 'escrow',
    description: 'Emitted when an escrow contract transitions state.',
    fields: {
      escrowId: {
        type: 'string',
        required: true,
        description: 'Identifier of the escrow contract.',
      },
      action: {
        type: 'string',
        required: true,
        description: 'Lifecycle transition action.',
        enumValues: ['deposited', 'withdrawn', 'refunded'],
      },
      token: {
        type: 'string',
        required: true,
        description: 'Token identifier or code.',
      },
      amount: {
        type: 'number',
        required: true,
        description: 'Escrow amount.',
      },
      receiptReference: {
        type: 'string',
        required: false,
        description: 'Optional deterministic receipt reference.',
      },
    },
  },
} as const;

export type RegisteredAnalyticsEventName = keyof typeof ANALYTICS_EVENT_SCHEMAS;

export const ALLOWED_ANALYTICS_FIELD_TYPES: readonly AnalyticsFieldType[] = [
  'string',
  'number',
  'boolean',
  'object',
  'array',
];

import { z } from 'zod';

export const PaymentLinkViewedSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  linkId: z.string(),
  amount: z.number().optional(),
  asset: z.string().optional(),
});

export const PaymentLinkErrorSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  linkId: z.string(),
  error: z.string(),
});

export const PaymentLinkRetrySchema = z.object({
  schemaVersion: z.literal(1).default(1),
  linkId: z.string(),
});

export const PaymentInitiatedSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  linkId: z.string(),
  transactionId: z.string(),
  amount: z.number(),
  asset: z.string(),
});

export const PaymentCompletedSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  linkId: z.string(),
  transactionId: z.string(),
  status: z.string(),
});

export const OnboardingEventSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  event_name: z.string(),
  timestamp: z.number(),
  session_id: z.string(),
}).catchall(z.unknown()); // Mobile passes variable params, we catchall the rest

// Central Registry
export const AnalyticsRegistry = {
  payment_link_viewed: PaymentLinkViewedSchema,
  payment_link_error: PaymentLinkErrorSchema,
  payment_link_retry: PaymentLinkRetrySchema,
  payment_initiated: PaymentInitiatedSchema,
  payment_completed: PaymentCompletedSchema,
  onboarding_event: OnboardingEventSchema,
} as const;

export type EventName = keyof typeof AnalyticsRegistry;

/**
 * Validates an event against the central registry.
 * Returns { valid: true, data: T } or { valid: false, error: ZodError }
 */
export function validateEvent(eventName: string, payload: unknown) {
  const schema = AnalyticsRegistry[eventName as EventName];
  if (!schema) {
    return { valid: false, error: new Error(`Unknown event name: ${eventName}`) };
  }
  
  const result = schema.safeParse(payload);
  if (result.success) {
    return { valid: true, data: result.data };
  } else {
    return { valid: false, error: result.error };
  }
}

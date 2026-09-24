import { z } from 'zod';

// Define the schemas for analytics events here.
// When changing these schemas, if you add a required field or remove a field, 
// you must increment the schema version.

export const EventSchemas = {
  payment_link_viewed: {
    version: 1,
    schema: z.object({
      link_id: z.string(),
      referer: z.string().optional(),
    }),
  },
  payment_link_error: {
    version: 1,
    schema: z.object({
      link_id: z.string(),
      error_message: z.string(),
    }),
  },
  payment_initiated: {
    version: 1,
    schema: z.object({
      link_id: z.string(),
      amount: z.number(),
      currency: z.string(),
    }),
  },
  payment_completed: {
    version: 1,
    schema: z.object({
      link_id: z.string(),
      transaction_id: z.string(),
      amount: z.number(),
      currency: z.string(),
    }),
  },
  payment_link_retry: {
    version: 1,
    schema: z.object({
      link_id: z.string(),
    }),
  },
} as const;

export type EventName = keyof typeof EventSchemas;

export type InferEventPayload<T extends EventName> = z.infer<typeof EventSchemas[T]['schema']>;

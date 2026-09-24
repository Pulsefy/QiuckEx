import { EventSchemas, EventName, InferEventPayload } from './schemas.js';
import { z } from 'zod';

export { EventSchemas, type EventName, type InferEventPayload };

export interface ValidationResult<T extends EventName> {
  valid: boolean;
  event: T;
  payload?: InferEventPayload<T>;
  errors?: z.ZodError;
}

let invalidEventCount = 0;

export function getInvalidEventCount(): number {
  return invalidEventCount;
}

export function validateEvent<T extends EventName>(
  eventName: T,
  payload: unknown
): ValidationResult<T> {
  const schemaDef = EventSchemas[eventName];
  if (!schemaDef) {
    invalidEventCount++;
    return {
      valid: false,
      event: eventName,
      errors: new z.ZodError([{
        code: z.ZodIssueCode.custom,
        path: [],
        message: `Schema not found for event: ${eventName}`,
      }]),
    };
  }

  const result = schemaDef.schema.safeParse(payload);
  if (result.success) {
    return {
      valid: true,
      event: eventName,
      payload: result.data as InferEventPayload<T>,
    };
  } else {
    invalidEventCount++;
    return {
      valid: false,
      event: eventName,
      errors: result.error,
    };
  }
}

export function exportRegistry() {
  const exported: Record<string, any> = {};
  for (const [eventName, schemaDef] of Object.entries(EventSchemas)) {
    // Basic extraction of JSON schema from Zod for external consumers.
    // In a real app we might use zod-to-json-schema, but doing a simplistic export here.
    const shape = (schemaDef.schema as any)._def.shape?.() || (schemaDef.schema as any).shape;
    const properties: Record<string, string> = {};
    const required: string[] = [];
    
    if (shape) {
      for (const [key, propSchema] of Object.entries(shape) as any) {
        const isOptional = propSchema.isOptional();
        if (!isOptional) {
          required.push(key);
        }
        properties[key] = propSchema._def.typeName;
      }
    }
    
    exported[eventName] = {
      version: schemaDef.version,
      properties,
      required,
    };
  }
  return exported;
}

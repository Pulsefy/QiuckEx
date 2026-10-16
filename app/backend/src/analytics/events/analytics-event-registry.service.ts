import { Injectable, Logger, Optional } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { v4 as uuidv4 } from 'uuid';
import { MetricsService } from '../../metrics/metrics.service';
import {
  AnalyticsEventDefinition,
  AnalyticsEventEnvelope,
  AnalyticsFieldType,
  AnalyticsRejectionReason,
  AnalyticsValidationIssue,
  AnalyticsValidationResult,
  EmitAnalyticsEventInput,
  EmitAnalyticsEventResult,
  ExportedAnalyticsEventSchema,
  ExportedAnalyticsSchemaRegistry,
} from './analytics-event-schema.types';
import { ANALYTICS_EVENT_SCHEMAS } from './analytics-event-schemas';

export const ANALYTICS_REGISTRY_VERSION = 1;

@Injectable()
export class AnalyticsEventRegistryService {
  private readonly logger = new Logger(AnalyticsEventRegistryService.name);
  private readonly schemas = new Map<string, AnalyticsEventDefinition>();
  private readonly recordedEvents: AnalyticsEventEnvelope[] = [];

  private acceptedCount = 0;
  private rejectedCount = 0;
  private readonly rejectedByReason = new Map<AnalyticsRejectionReason, number>();
  private readonly rejectedByEvent = new Map<string, number>();

  constructor(
    @Optional() private readonly eventEmitter?: EventEmitter2,
    @Optional() private readonly metricsService?: MetricsService,
  ) {
    this.loadDefaultSchemas();
  }

  private loadDefaultSchemas(): void {
    for (const definition of Object.values(ANALYTICS_EVENT_SCHEMAS)) {
      this.registerSchema(definition);
    }
  }

  /**
   * Registers or updates an event schema in the registry.
   * Enforces valid event name and positive integer version.
   */
  registerSchema(definition: AnalyticsEventDefinition): void {
    if (!definition.eventName || typeof definition.eventName !== 'string') {
      throw new Error('Analytics event schema must have a non-empty eventName.');
    }
    if (!Number.isInteger(definition.version) || definition.version < 1) {
      throw new Error(
        `Analytics event "${definition.eventName}" must have an integer version >= 1.`,
      );
    }
    this.schemas.set(definition.eventName, definition);
  }

  /**
   * Retrieves a registered schema by event name.
   */
  getSchema(eventName: string): AnalyticsEventDefinition | undefined {
    return this.schemas.get(eventName);
  }

  /**
   * Lists all registered event schemas.
   */
  listSchemas(): AnalyticsEventDefinition[] {
    return Array.from(this.schemas.values());
  }

  /**
   * Validates an event payload against its registered versioned schema without recording it.
   */
  validate(
    eventName: string,
    payload: unknown,
    options?: { schemaVersion?: number; allowExtraFields?: boolean },
  ): AnalyticsValidationResult {
    const schema = this.schemas.get(eventName);

    if (!schema) {
      return {
        valid: false,
        eventName,
        schemaVersion: options?.schemaVersion ?? null,
        issues: [
          {
            reason: 'unknown_event',
            message: `Analytics event "${eventName}" is not registered in the central schema registry.`,
          },
        ],
      };
    }

    const issues: AnalyticsValidationIssue[] = [];
    const targetVersion = options?.schemaVersion ?? schema.version;

    if (targetVersion !== schema.version) {
      issues.push({
        reason: 'version_mismatch',
        message: `Event "${eventName}" emitted with schemaVersion v${targetVersion}, but registry version is v${schema.version}.`,
      });
    }

    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      issues.push({
        reason: 'invalid_payload',
        message: `Payload for event "${eventName}" must be a non-null plain object.`,
      });
      return {
        valid: false,
        eventName,
        schemaVersion: schema.version,
        issues,
      };
    }

    const record = payload as Record<string, unknown>;

    // Validate declared fields
    for (const [fieldName, fieldSchema] of Object.entries(schema.fields)) {
      const value = record[fieldName];

      if (value === undefined || value === null) {
        if (fieldSchema.required) {
          issues.push({
            field: fieldName,
            reason: 'missing_required_field',
            message: `Required field "${fieldName}" is missing on event "${eventName}" (v${schema.version}).`,
          });
        }
        continue;
      }

      if (!this.matchesFieldType(value, fieldSchema.type)) {
        issues.push({
          field: fieldName,
          reason: 'invalid_field_type',
          message: `Field "${fieldName}" on event "${eventName}" expected type "${fieldSchema.type}", received "${this.describeValueType(value)}".`,
        });
        continue;
      }

      if (
        fieldSchema.enumValues &&
        fieldSchema.enumValues.length > 0 &&
        (typeof value !== 'string' || !fieldSchema.enumValues.includes(value))
      ) {
        issues.push({
          field: fieldName,
          reason: 'invalid_enum_value',
          message: `Field "${fieldName}" on event "${eventName}" must be one of [${fieldSchema.enumValues.join(', ')}], received "${String(value)}".`,
        });
      }
    }

    // Reject undeclared fields unless explicitly opted out
    if (!options?.allowExtraFields) {
      for (const key of Object.keys(record)) {
        if (!(key in schema.fields)) {
          issues.push({
            field: key,
            reason: 'unexpected_field',
            message: `Undeclared field "${key}" is not allowed on event "${eventName}" (v${schema.version}).`,
          });
        }
      }
    }

    return {
      valid: issues.length === 0,
      eventName,
      schemaVersion: schema.version,
      issues,
    };
  }

  /**
   * Validates an analytics event against its versioned schema before recording and emitting it.
   * Invalid events are rejected and counted (both in-memory and in Prometheus metrics).
   */
  emit(input: EmitAnalyticsEventInput): EmitAnalyticsEventResult {
    const validation = this.validate(input.eventName, input.payload, {
      schemaVersion: input.schemaVersion,
      allowExtraFields: input.allowExtraFields,
    });

    if (!validation.valid) {
      this.recordRejection(input.eventName, validation);
      return {
        accepted: false,
        validation,
      };
    }

    const schemaVersion = validation.schemaVersion!;
    const envelope: AnalyticsEventEnvelope = {
      eventId: uuidv4(),
      eventName: input.eventName,
      schemaVersion,
      occurredAt: input.occurredAt ?? new Date().toISOString(),
      payload: { ...input.payload },
      ...(input.metadata ? { metadata: { ...input.metadata } } : {}),
    };

    this.acceptedCount += 1;
    this.recordedEvents.push(envelope);
    if (this.recordedEvents.length > 1000) {
      this.recordedEvents.shift();
    }

    this.metricsService?.recordAnalyticsEventAccepted(input.eventName, schemaVersion);
    this.eventEmitter?.emit(`analytics.${input.eventName}`, envelope);

    return {
      accepted: true,
      event: envelope,
      validation,
    };
  }

  /**
   * Returns current validation/rejection counters for observability and testing.
   */
  getValidationStats(): {
    acceptedCount: number;
    rejectedCount: number;
    rejectedByReason: Record<string, number>;
    rejectedByEvent: Record<string, number>;
  } {
    return {
      acceptedCount: this.acceptedCount,
      rejectedCount: this.rejectedCount,
      rejectedByReason: Object.fromEntries(this.rejectedByReason.entries()),
      rejectedByEvent: Object.fromEntries(this.rejectedByEvent.entries()),
    };
  }

  /**
   * Returns recently recorded valid events.
   */
  getRecordedEvents(): ReadonlyArray<AnalyticsEventEnvelope> {
    return this.recordedEvents;
  }

  /**
   * Exports a single event schema in a machine-readable format (including JSON Schema Draft 2020-12)
   * suitable for dashboards and downstream consumers.
   */
  exportEventSchema(eventName: string): ExportedAnalyticsEventSchema | undefined {
    const def = this.schemas.get(eventName);
    if (!def) {
      return undefined;
    }

    const requiredFields: string[] = [];
    const optionalFields: string[] = [];
    const fields = Object.entries(def.fields).map(([name, field]) => {
      if (field.required) {
        requiredFields.push(name);
      } else {
        optionalFields.push(name);
      }

      return {
        name,
        type: field.type,
        required: field.required,
        description: field.description,
        ...(field.enumValues && field.enumValues.length > 0
          ? { enumValues: [...field.enumValues] }
          : {}),
      };
    });

    const properties: ExportedAnalyticsEventSchema['jsonSchema']['properties'] = {};
    for (const [name, field] of Object.entries(def.fields)) {
      properties[name] = {
        type: field.type,
        description: field.description,
        ...(field.enumValues && field.enumValues.length > 0
          ? { enum: [...field.enumValues] }
          : {}),
      };
    }

    return {
      eventName: def.eventName,
      version: def.version,
      category: def.category,
      description: def.description,
      deprecated: Boolean(def.deprecated),
      requiredFields,
      optionalFields,
      fields,
      jsonSchema: {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        $id: `https://quickex.io/schemas/analytics/${def.eventName}/v${def.version}.json`,
        title: `${def.eventName} (v${def.version})`,
        description: def.description,
        type: 'object',
        additionalProperties: false,
        required: requiredFields,
        properties,
      },
    };
  }

  /**
   * Exports the full central schema registry for dashboards and consumers.
   */
  exportRegistry(): ExportedAnalyticsSchemaRegistry {
    const events = Array.from(this.schemas.keys())
      .sort((a, b) => a.localeCompare(b))
      .map((name) => this.exportEventSchema(name)!)
      .filter(Boolean);

    return {
      registryVersion: ANALYTICS_REGISTRY_VERSION,
      generatedAt: new Date().toISOString(),
      totalEvents: events.length,
      events,
    };
  }

  private recordRejection(
    eventName: string,
    validation: AnalyticsValidationResult,
  ): void {
    this.rejectedCount += 1;
    this.rejectedByEvent.set(
      eventName,
      (this.rejectedByEvent.get(eventName) ?? 0) + 1,
    );

    const primaryReason = validation.issues[0]?.reason ?? 'invalid_payload';
    for (const issue of validation.issues) {
      this.rejectedByReason.set(
        issue.reason,
        (this.rejectedByReason.get(issue.reason) ?? 0) + 1,
      );
    }

    this.metricsService?.recordAnalyticsEventRejected(
      eventName,
      validation.schemaVersion,
      primaryReason,
    );

    this.logger.warn(
      `Rejected invalid analytics event "${eventName}" (version=${validation.schemaVersion ?? 'unknown'}): ${validation.issues
        .map((i) => i.message)
        .join('; ')}`,
    );
  }

  private matchesFieldType(value: unknown, expectedType: AnalyticsFieldType): boolean {
    switch (expectedType) {
      case 'string':
        return typeof value === 'string';
      case 'number':
        return typeof value === 'number' && Number.isFinite(value);
      case 'boolean':
        return typeof value === 'boolean';
      case 'array':
        return Array.isArray(value);
      case 'object':
        return typeof value === 'object' && value !== null && !Array.isArray(value);
      default:
        return false;
    }
  }

  private describeValueType(value: unknown): string {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    if (typeof value === 'number' && !Number.isFinite(value)) return 'non-finite-number';
    return typeof value;
  }
}

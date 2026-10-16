export type AnalyticsFieldType = 'string' | 'number' | 'boolean' | 'object' | 'array';

export interface AnalyticsFieldSchema {
  type: AnalyticsFieldType;
  required: boolean;
  description: string;
  enumValues?: readonly string[];
}

export interface AnalyticsEventDefinition {
  eventName: string;
  version: number;
  category: 'payment' | 'link' | 'refund' | 'escrow' | 'user' | 'system';
  description: string;
  fields: Readonly<Record<string, AnalyticsFieldSchema>>;
  deprecated?: boolean;
}

export type AnalyticsRejectionReason =
  | 'unknown_event'
  | 'version_mismatch'
  | 'missing_required_field'
  | 'invalid_field_type'
  | 'invalid_enum_value'
  | 'unexpected_field'
  | 'invalid_payload';

export interface AnalyticsValidationIssue {
  field?: string;
  reason: AnalyticsRejectionReason;
  message: string;
}

export interface AnalyticsValidationResult {
  valid: boolean;
  eventName: string;
  schemaVersion: number | null;
  issues: AnalyticsValidationIssue[];
}

export interface AnalyticsEventEnvelope<TPayload extends Record<string, unknown> = Record<string, unknown>> {
  eventId: string;
  eventName: string;
  schemaVersion: number;
  occurredAt: string;
  payload: TPayload;
  metadata?: Record<string, unknown>;
}

export interface EmitAnalyticsEventInput {
  eventName: string;
  payload: Record<string, unknown>;
  schemaVersion?: number;
  occurredAt?: string;
  metadata?: Record<string, unknown>;
  allowExtraFields?: boolean;
}

export interface EmitAnalyticsEventResult {
  accepted: boolean;
  event?: AnalyticsEventEnvelope;
  validation: AnalyticsValidationResult;
}

export interface ExportedAnalyticsFieldSchema {
  name: string;
  type: AnalyticsFieldType;
  required: boolean;
  description: string;
  enumValues?: readonly string[];
}

export interface ExportedAnalyticsEventSchema {
  eventName: string;
  version: number;
  category: string;
  description: string;
  deprecated: boolean;
  requiredFields: string[];
  optionalFields: string[];
  fields: ExportedAnalyticsFieldSchema[];
  jsonSchema: {
    $schema: string;
    $id: string;
    title: string;
    description: string;
    type: 'object';
    additionalProperties: boolean;
    required: string[];
    properties: Record<
      string,
      {
        type: AnalyticsFieldType;
        description: string;
        enum?: readonly string[];
      }
    >;
  };
}

export interface ExportedAnalyticsSchemaRegistry {
  registryVersion: number;
  generatedAt: string;
  totalEvents: number;
  events: ExportedAnalyticsEventSchema[];
}

export interface SchemaBreakingChange {
  eventName: string;
  previousVersion: number;
  currentVersion: number;
  changeType:
    | 'event_removed'
    | 'version_regressed'
    | 'field_removed'
    | 'required_field_added'
    | 'field_made_required'
    | 'field_type_changed'
    | 'enum_values_narrowed';
  field?: string;
  message: string;
}

export interface SchemaCompatibilityReport {
  compatible: boolean;
  breakingChanges: SchemaBreakingChange[];
}

export interface BaselineSchemaSnapshotEntry {
  eventName: string;
  version: number;
  fields: Record<
    string,
    {
      type: AnalyticsFieldType;
      required: boolean;
      enumValues?: readonly string[];
    }
  >;
}

export interface BaselineSchemaSnapshot {
  snapshotFormatVersion: 1;
  events: Record<string, BaselineSchemaSnapshotEntry>;
}

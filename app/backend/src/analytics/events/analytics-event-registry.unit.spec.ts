import { EventEmitter2 } from '@nestjs/event-emitter';
import { MetricsService } from '../../metrics/metrics.service';
import {
  ANALYTICS_EVENT_SCHEMAS,
  ALLOWED_ANALYTICS_FIELD_TYPES,
  AnalyticsEventDefinition,
  AnalyticsEventRegistryService,
  assertAnalyticsSchemasCompatible,
  buildSchemaSnapshot,
  checkAnalyticsSchemaCompatibility,
  loadBaselineSchemaSnapshot,
} from './index';

describe('AnalyticsEventRegistryService & Schema Compatibility', () => {
  let registry: AnalyticsEventRegistryService;
  let mockEventEmitter: { emit: jest.Mock };
  let mockMetricsService: {
    recordAnalyticsEventAccepted: jest.Mock;
    recordAnalyticsEventRejected: jest.Mock;
  };

  beforeEach(() => {
    mockEventEmitter = {
      emit: jest.fn(),
    };
    mockMetricsService = {
      recordAnalyticsEventAccepted: jest.fn(),
      recordAnalyticsEventRejected: jest.fn(),
    };

    registry = new AnalyticsEventRegistryService(
      mockEventEmitter as unknown as EventEmitter2,
      mockMetricsService as unknown as MetricsService,
    );
  });

  describe('Central Schema Registry', () => {
    it('ensures every analytics event in ANALYTICS_EVENT_SCHEMAS has a valid versioned schema', () => {
      const schemas = registry.listSchemas();
      expect(schemas.length).toBeGreaterThanOrEqual(6);

      for (const schema of schemas) {
        expect(schema.eventName).toMatch(/^[a-z0-9]+(\.[a-z0-9_]+)+$/);
        expect(Number.isInteger(schema.version)).toBe(true);
        expect(schema.version).toBeGreaterThanOrEqual(1);
        expect(schema.description.length).toBeGreaterThan(5);
        expect(Object.keys(schema.fields).length).toBeGreaterThan(0);

        for (const [fieldName, fieldDef] of Object.entries(schema.fields)) {
          expect(fieldName.length).toBeGreaterThan(0);
          expect(ALLOWED_ANALYTICS_FIELD_TYPES).toContain(fieldDef.type);
          expect(typeof fieldDef.required).toBe('boolean');
          expect(fieldDef.description.length).toBeGreaterThan(0);
        }
      }
    });

    it('rejects registering a schema with an invalid version or empty eventName', () => {
      expect(() =>
        registry.registerSchema({
          eventName: '',
          version: 1,
          category: 'system',
          description: 'Invalid name',
          fields: {},
        }),
      ).toThrow(/non-empty eventName/);

      expect(() =>
        registry.registerSchema({
          eventName: 'system.invalid',
          version: 0,
          category: 'system',
          description: 'Invalid version',
          fields: {},
        }),
      ).toThrow(/integer version >= 1/);
    });
  });

  describe('Emit-Time Validation and Rejection Counting', () => {
    it('validates and records a valid event and increments accepted metrics', () => {
      const result = registry.emit({
        eventName: 'payment.completed',
        payload: {
          paymentId: 'pay_001',
          txHash: 'a1b2c3d4',
          asset: 'USDC',
          amount: 100,
          amountUsd: 100,
          settlementLatencyMs: 850,
        },
      });

      expect(result.accepted).toBe(true);
      expect(result.validation.valid).toBe(true);
      expect(result.validation.issues).toEqual([]);
      expect(result.event).toBeDefined();
      expect(result.event?.schemaVersion).toBe(1);
      expect(result.event?.eventName).toBe('payment.completed');

      expect(mockMetricsService.recordAnalyticsEventAccepted).toHaveBeenCalledWith(
        'payment.completed',
        1,
      );
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'analytics.payment.completed',
        result.event,
      );

      const stats = registry.getValidationStats();
      expect(stats.acceptedCount).toBe(1);
      expect(stats.rejectedCount).toBe(0);
      expect(registry.getRecordedEvents()).toHaveLength(1);
    });

    it('rejects unknown events and increments rejection counters', () => {
      const result = registry.emit({
        eventName: 'unregistered.event',
        payload: { foo: 'bar' },
      });

      expect(result.accepted).toBe(false);
      expect(result.event).toBeUndefined();
      expect(result.validation.valid).toBe(false);
      expect(result.validation.issues[0]?.reason).toBe('unknown_event');

      expect(mockMetricsService.recordAnalyticsEventRejected).toHaveBeenCalledWith(
        'unregistered.event',
        null,
        'unknown_event',
      );
      expect(mockEventEmitter.emit).not.toHaveBeenCalled();

      const stats = registry.getValidationStats();
      expect(stats.acceptedCount).toBe(0);
      expect(stats.rejectedCount).toBe(1);
      expect(stats.rejectedByReason.unknown_event).toBe(1);
      expect(stats.rejectedByEvent['unregistered.event']).toBe(1);
    });

    it('rejects events missing required fields and counts the rejection', () => {
      const result = registry.emit({
        eventName: 'payment.completed',
        payload: {
          paymentId: 'pay_002',
          // txHash and amountUsd are missing
          asset: 'XLM',
          amount: 50,
        },
      });

      expect(result.accepted).toBe(false);
      expect(result.validation.valid).toBe(false);
      expect(result.validation.issues.map((i) => i.field)).toEqual(
        expect.arrayContaining(['txHash', 'amountUsd']),
      );
      expect(result.validation.issues.every((i) => i.reason === 'missing_required_field')).toBe(
        true,
      );

      const stats = registry.getValidationStats();
      expect(stats.rejectedCount).toBe(1);
      expect(stats.rejectedByReason.missing_required_field).toBe(2);
      expect(registry.getRecordedEvents()).toHaveLength(0);
    });

    it('rejects events with wrong field types, invalid enum values, or undeclared fields', () => {
      const result = registry.emit({
        eventName: 'link.created',
        payload: {
          linkId: 'lnk_1',
          linkType: 'unsupported_type',
          asset: 'USDC',
          isPrivate: 'yes' as unknown as boolean,
          undeclaredField: 123,
        },
      });

      expect(result.accepted).toBe(false);
      const reasons = result.validation.issues.map((i) => i.reason);
      expect(reasons).toContain('invalid_enum_value');
      expect(reasons).toContain('invalid_field_type');
      expect(reasons).toContain('unexpected_field');

      const stats = registry.getValidationStats();
      expect(stats.rejectedCount).toBe(1);
      expect(stats.rejectedByReason.invalid_enum_value).toBe(1);
      expect(stats.rejectedByReason.invalid_field_type).toBe(1);
      expect(stats.rejectedByReason.unexpected_field).toBe(1);
    });

    it('rejects events emitted with a mismatched schemaVersion', () => {
      const result = registry.emit({
        eventName: 'refund.requested',
        schemaVersion: 99,
        payload: {
          refundId: 'ref_1',
          paymentId: 'pay_1',
          amountUsd: 10,
        },
      });

      expect(result.accepted).toBe(false);
      expect(result.validation.issues[0]?.reason).toBe('version_mismatch');
      expect(registry.getValidationStats().rejectedByReason.version_mismatch).toBe(1);
    });
  });

  describe('Export for Dashboards and Consumers', () => {
    it('exports the full registry with JSON Schema Draft 2020-12 definitions', () => {
      const exported = registry.exportRegistry();

      expect(exported.registryVersion).toBe(1);
      expect(exported.totalEvents).toBe(Object.keys(ANALYTICS_EVENT_SCHEMAS).length);
      expect(exported.events).toHaveLength(exported.totalEvents);

      const paymentCompleted = exported.events.find(
        (e) => e.eventName === 'payment.completed',
      );
      expect(paymentCompleted).toBeDefined();
      expect(paymentCompleted?.version).toBe(1);
      expect(paymentCompleted?.requiredFields).toEqual([
        'paymentId',
        'txHash',
        'asset',
        'amount',
        'amountUsd',
      ]);
      expect(paymentCompleted?.optionalFields).toEqual([
        'settlementLatencyMs',
        'organizationId',
      ]);
      expect(paymentCompleted?.jsonSchema.$schema).toBe(
        'https://json-schema.org/draft/2020-12/schema',
      );
      expect(paymentCompleted?.jsonSchema.additionalProperties).toBe(false);
      expect(paymentCompleted?.jsonSchema.required).toContain('amountUsd');
      expect(paymentCompleted?.jsonSchema.properties.amountUsd.type).toBe('number');
    });
  });

  describe('CI Schema Evolution & Breaking Change Detection', () => {
    it('verifies the committed baseline snapshot is compatible with ANALYTICS_EVENT_SCHEMAS', () => {
      const baseline = loadBaselineSchemaSnapshot();
      expect(() =>
        assertAnalyticsSchemasCompatible(baseline, ANALYTICS_EVENT_SCHEMAS),
      ).not.toThrow();
    });

    it('fails when a required field is added without incrementing schema version', () => {
      const baseline = buildSchemaSnapshot(ANALYTICS_EVENT_SCHEMAS);
      const mutated: Record<string, AnalyticsEventDefinition> = {
        ...ANALYTICS_EVENT_SCHEMAS,
        'payment.completed': {
          ...ANALYTICS_EVENT_SCHEMAS['payment.completed'],
          version: 1, // NOT incremented
          fields: {
            ...ANALYTICS_EVENT_SCHEMAS['payment.completed'].fields,
            newMandatoryField: {
              type: 'string',
              required: true,
              description: 'Breaking new required field',
            },
          },
        },
      };

      const report = checkAnalyticsSchemaCompatibility(baseline, mutated);
      expect(report.compatible).toBe(false);
      expect(report.breakingChanges).toEqual([
        expect.objectContaining({
          eventName: 'payment.completed',
          changeType: 'required_field_added',
          field: 'newMandatoryField',
          previousVersion: 1,
          currentVersion: 1,
        }),
      ]);

      expect(() => assertAnalyticsSchemasCompatible(baseline, mutated)).toThrow(
        /Analytics event schema compatibility check failed/,
      );
    });

    it('fails when a field is removed without incrementing schema version', () => {
      const baseline = buildSchemaSnapshot(ANALYTICS_EVENT_SCHEMAS);
      const { settlementLatencyMs: _removed, ...remainingFields } =
        ANALYTICS_EVENT_SCHEMAS['payment.completed'].fields;

      const mutated: Record<string, AnalyticsEventDefinition> = {
        ...ANALYTICS_EVENT_SCHEMAS,
        'payment.completed': {
          ...ANALYTICS_EVENT_SCHEMAS['payment.completed'],
          version: 1, // NOT incremented
          fields: remainingFields,
        },
      };

      const report = checkAnalyticsSchemaCompatibility(baseline, mutated);
      expect(report.compatible).toBe(false);
      expect(report.breakingChanges).toEqual([
        expect.objectContaining({
          eventName: 'payment.completed',
          changeType: 'field_removed',
          field: 'settlementLatencyMs',
        }),
      ]);
    });

    it('fails when an optional field becomes required or changes type without incrementing version', () => {
      const baseline = buildSchemaSnapshot(ANALYTICS_EVENT_SCHEMAS);
      const mutated: Record<string, AnalyticsEventDefinition> = {
        ...ANALYTICS_EVENT_SCHEMAS,
        'payment.initiated': {
          ...ANALYTICS_EVENT_SCHEMAS['payment.initiated'],
          version: 1,
          fields: {
            ...ANALYTICS_EVENT_SCHEMAS['payment.initiated'].fields,
            amountUsd: {
              type: 'string', // changed from number
              required: true, // changed from false
              description: 'Mutated field',
            },
          },
        },
      };

      const report = checkAnalyticsSchemaCompatibility(baseline, mutated);
      expect(report.compatible).toBe(false);
      expect(report.breakingChanges.map((c) => c.changeType)).toEqual(
        expect.arrayContaining(['field_type_changed', 'field_made_required']),
      );
    });

    it('allows adding a required field or removing a field when schema version IS incremented', () => {
      const baseline = buildSchemaSnapshot(ANALYTICS_EVENT_SCHEMAS);
      const { settlementLatencyMs: _removed, ...remainingFields } =
        ANALYTICS_EVENT_SCHEMAS['payment.completed'].fields;

      const mutatedWithBump: Record<string, AnalyticsEventDefinition> = {
        ...ANALYTICS_EVENT_SCHEMAS,
        'payment.completed': {
          ...ANALYTICS_EVENT_SCHEMAS['payment.completed'],
          version: 2, // Incremented!
          fields: {
            ...remainingFields,
            merchantFeeUsd: {
              type: 'number',
              required: true,
              description: 'New required field in v2',
            },
          },
        },
      };

      const report = checkAnalyticsSchemaCompatibility(baseline, mutatedWithBump);
      expect(report.compatible).toBe(true);
      expect(report.breakingChanges).toEqual([]);
    });

    it('allows adding an optional field without incrementing schema version', () => {
      const baseline = buildSchemaSnapshot(ANALYTICS_EVENT_SCHEMAS);
      const mutatedOptional: Record<string, AnalyticsEventDefinition> = {
        ...ANALYTICS_EVENT_SCHEMAS,
        'payment.completed': {
          ...ANALYTICS_EVENT_SCHEMAS['payment.completed'],
          version: 1,
          fields: {
            ...ANALYTICS_EVENT_SCHEMAS['payment.completed'].fields,
            memoType: {
              type: 'string',
              required: false,
              description: 'Backwards-compatible optional field',
            },
          },
        },
      };

      const report = checkAnalyticsSchemaCompatibility(baseline, mutatedOptional);
      expect(report.compatible).toBe(true);
      expect(report.breakingChanges).toEqual([]);
    });
  });
});

import { BadRequestException, NotFoundException } from '@nestjs/common';
import { AnalyticsController } from './analytics.controller';
import { AnalyticsService } from './analytics.service';
import { AnalyticsEventRegistryService } from './events/analytics-event-registry.service';

describe('AnalyticsController — Event Schema Registry & Validation Endpoints', () => {
  let controller: AnalyticsController;
  let registry: AnalyticsEventRegistryService;

  beforeEach(() => {
    registry = new AnalyticsEventRegistryService();
    const mockAnalyticsService = {} as unknown as AnalyticsService;
    controller = new AnalyticsController(mockAnalyticsService, registry);
  });

  it('GET /analytics/schemas exports the central schema registry for dashboards and consumers', () => {
    const exported = controller.getSchemas();
    expect(exported.registryVersion).toBe(1);
    expect(exported.totalEvents).toBeGreaterThanOrEqual(6);
    expect(Array.isArray(exported.events)).toBe(true);
    expect(exported.events[0]).toHaveProperty('jsonSchema');
  });

  it('GET /analytics/schemas/:eventName returns a single event schema or throws NotFoundException', () => {
    const schema = controller.getEventSchema('payment.completed');
    expect(schema.eventName).toBe('payment.completed');
    expect(schema.version).toBe(1);
    expect(schema.requiredFields).toContain('amountUsd');

    expect(() => controller.getEventSchema('non.existent')).toThrow(
      NotFoundException,
    );
  });

  it('POST /analytics/events validates and records valid events, and rejects invalid events while incrementing stats', () => {
    const validResponse = controller.emitEvent({
      eventName: 'payment.initiated',
      payload: {
        paymentId: 'pay_100',
        asset: 'XLM',
        amount: 42,
      },
    });
    expect(validResponse.accepted).toBe(true);
    expect(validResponse.event?.schemaVersion).toBe(1);

    expect(() =>
      controller.emitEvent({
        eventName: 'payment.initiated',
        payload: {
          paymentId: 'pay_101',
          // missing required asset and amount
        },
      }),
    ).toThrow(BadRequestException);

    const stats = controller.getEventValidationStats();
    expect(stats.acceptedCount).toBe(1);
    expect(stats.rejectedCount).toBe(1);
    expect(stats.rejectedByReason.missing_required_field).toBe(2);
  });
});

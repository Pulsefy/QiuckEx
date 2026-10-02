import { Injectable, BadRequestException } from '@nestjs/common';
import * as Joi from 'joi';
import { MetricsService } from '../metrics/metrics.service';

export interface AnalyticsEventSchema {
  eventName: string;
  version: number;
  description: string;
  schema: Joi.ObjectSchema;
}

@Injectable()
export class SchemaRegistryService {
  private schemas: Map<string, AnalyticsEventSchema> = new Map();

  constructor(private readonly metricsService: MetricsService) {
    this.registerSchemas();
  }

  private registerSchemas() {
    this.register({
      eventName: 'page_view',
      version: 1,
      description: 'Recorded when a user views a page',
      schema: Joi.object({
        path: Joi.string().required(),
        userId: Joi.string().optional(),
      }),
    });
    this.register({
      eventName: 'payment_initiated',
      version: 1,
      description: 'Recorded when a payment is initiated',
      schema: Joi.object({
        paymentId: Joi.string().required(),
        amount: Joi.number().required(),
        asset: Joi.string().required(),
      }),
    });
  }

  register(schemaDef: AnalyticsEventSchema) {
    const key = `${schemaDef.eventName}@v${schemaDef.version}`;
    if (this.schemas.has(key)) {
      throw new Error(`Schema already registered: ${key}`);
    }
    this.schemas.set(key, schemaDef);
  }

  getSchema(eventName: string, version: number): AnalyticsEventSchema | undefined {
    return this.schemas.get(`${eventName}@v${version}`);
  }

  validateEvent(eventName: string, version: number, payload: any): any {
    const schemaDef = this.getSchema(eventName, version);
    if (!schemaDef) {
      this.metricsService.recordError('analytics', 'unknown_schema');
      throw new BadRequestException(`Unknown analytics event schema: ${eventName}@v${version}`);
    }

    const { error, value } = schemaDef.schema.validate(payload, { stripUnknown: true, abortEarly: false });
    if (error) {
      this.metricsService.recordError('analytics', 'invalid_event_schema');
      throw new BadRequestException(`Invalid event payload for ${eventName}@v${version}: ${error.message}`);
    }

    return value;
  }

  exportRegistry(): any[] {
    return Array.from(this.schemas.values()).map(def => ({
      eventName: def.eventName,
      version: def.version,
      description: def.description,
      schema: def.schema.describe(),
    }));
  }
}

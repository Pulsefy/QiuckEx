import { Test, TestingModule } from '@nestjs/testing';
import { SchemaRegistryService } from './schema-registry.service';
import { MetricsService } from '../metrics/metrics.service';
import { BadRequestException } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';

describe('SchemaRegistryService', () => {
  let service: SchemaRegistryService;
  let metricsService: jest.Mocked<MetricsService>;

  beforeEach(async () => {
    metricsService = {
      recordError: jest.fn(),
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SchemaRegistryService,
        {
          provide: MetricsService,
          useValue: metricsService,
        },
      ],
    }).compile();

    service = module.get<SchemaRegistryService>(SchemaRegistryService);
  });

  it('should validate a correct event', () => {
    const payload = { path: '/home' };
    const result = service.validateEvent('page_view', 1, payload);
    expect(result).toEqual(payload);
  });

  it('should reject an event with missing required fields', () => {
    const payload = { userId: '123' }; // missing path
    expect(() => service.validateEvent('page_view', 1, payload)).toThrow(BadRequestException);
    expect(metricsService.recordError).toHaveBeenCalledWith('analytics', 'invalid_event_schema');
  });

  it('should reject unknown schema versions', () => {
    const payload = { path: '/home' };
    expect(() => service.validateEvent('page_view', 2, payload)).toThrow(BadRequestException);
    expect(metricsService.recordError).toHaveBeenCalledWith('analytics', 'unknown_schema');
  });

  it('fails CI if schema version is mutated (schema registry snapshot match)', () => {
    const snapshotPath = path.join(__dirname, 'schemas-snapshot.json');
    const currentExport = service.exportRegistry();
    
    // Normalize Joi describe output by removing any unstable fields if they exist, but generally describe() is stable.
    const normalizedExport = JSON.parse(JSON.stringify(currentExport));

    if (!fs.existsSync(snapshotPath)) {
      fs.writeFileSync(snapshotPath, JSON.stringify(normalizedExport, null, 2));
      console.log('Created schemas snapshot');
      return;
    }

    const snapshot = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));

    for (const snapSchema of snapshot) {
      const currentSchema = normalizedExport.find(
        (s: any) => s.eventName === snapSchema.eventName && s.version === snapSchema.version
      );
      
      expect(currentSchema).toBeDefined();
      expect(currentSchema.schema).toEqual(snapSchema.schema);
    }
  });
});

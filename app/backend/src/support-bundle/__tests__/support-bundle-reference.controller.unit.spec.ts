import { Test, TestingModule } from '@nestjs/testing';
import type { Request } from 'express';

import { SupportBundleReferenceController } from '../support-bundle-reference.controller';
import { SupportBundleReferenceService } from '../support-bundle-reference.service';
import { SupportBundleReferenceResponseDto } from '../dto/support-bundle-reference.dto';
import { ApiKeyGuard } from '../../auth/guards/api-key.guard';

describe('SupportBundleReferenceController', () => {
  let controller: SupportBundleReferenceController;
  let service: jest.Mocked<SupportBundleReferenceService>;

  const mockReference: SupportBundleReferenceResponseDto = {
    id: 'ref-1',
    bundleIdMasked: 'bund****3d4b',
    targetType: 'receipt',
    targetId: 'rcpt_abc123_0',
    createdAt: '2026-07-27T12:00:00.000Z',
    expiresAt: '2026-08-26T12:00:00.000Z',
    redacted: false,
  };

  const mockRequest = { apiKey: { id: 'api-key-1' } } as unknown as Request;

  beforeEach(async () => {
    const mockService = {
      create: jest.fn().mockResolvedValue(mockReference),
      findById: jest.fn().mockResolvedValue(mockReference),
      findByTarget: jest.fn().mockResolvedValue([mockReference]),
      redact: jest.fn().mockResolvedValue({ ...mockReference, redacted: true }),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SupportBundleReferenceController],
      providers: [{ provide: SupportBundleReferenceService, useValue: mockService }],
    })
      .overrideGuard(ApiKeyGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<SupportBundleReferenceController>(SupportBundleReferenceController);
    service = module.get(SupportBundleReferenceService) as jest.Mocked<SupportBundleReferenceService>;
  });

  describe('create', () => {
    it('creates a reference using the caller api key as createdBy', async () => {
      const dto = { bundleId: 'bundle-1', targetType: 'receipt' as const, targetId: 'rcpt_abc123_0' };

      const result = await controller.create(dto, mockRequest);

      expect(result).toEqual(mockReference);
      expect(service.create).toHaveBeenCalledWith(dto, 'api-key-1');
    });

    it('falls back to "api" when no api key is attached to the request', async () => {
      const dto = { bundleId: 'bundle-1', targetType: 'receipt' as const, targetId: 'rcpt_abc123_0' };

      await controller.create(dto, {} as Request);

      expect(service.create).toHaveBeenCalledWith(dto, 'api');
    });
  });

  describe('findByTarget', () => {
    it('looks up references by target type and id', async () => {
      const result = await controller.findByTarget({
        targetType: 'receipt',
        targetId: 'rcpt_abc123_0',
      });

      expect(result).toEqual([mockReference]);
      expect(service.findByTarget).toHaveBeenCalledWith('receipt', 'rcpt_abc123_0');
    });
  });

  describe('findById', () => {
    it('returns a single reference', async () => {
      const result = await controller.findById('ref-1');

      expect(result).toEqual(mockReference);
      expect(service.findById).toHaveBeenCalledWith('ref-1');
    });
  });

  describe('redact', () => {
    it('redacts a reference using the caller api key as redactedBy', async () => {
      const result = await controller.redact('ref-1', mockRequest);

      expect(result.redacted).toBe(true);
      expect(service.redact).toHaveBeenCalledWith('ref-1', 'api-key-1');
    });
  });
});

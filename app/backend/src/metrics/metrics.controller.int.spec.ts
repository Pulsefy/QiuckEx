import { Test, TestingModule } from '@nestjs/testing';
import { MetricsController } from './metrics.controller';
import { MetricsService } from './metrics.service';
import { MetricsGuard } from './metrics.guard';
import { InternalServerErrorException } from '@nestjs/common';

const mockMetricsService = {
  getRegistry: jest.fn(),
};

const mockRegistry = {
  metrics: jest.fn().mockResolvedValue('# HELP mock metrics\n# TYPE mock gauge\nmock_metric 1'),
  contentType: 'text/plain; version=0.0.4',
};

jest.mock('./metrics.guard', () => ({
  MetricsGuard: jest.fn().mockImplementation(() => ({
    canActivate: jest.fn(() => true),
  })),
}));

describe('MetricsController', () => {
  let controller: MetricsController;
  let metricsService: MetricsService;

  beforeEach(async () => {
    jest.clearAllMocks();
    
    mockRegistry.metrics.mockResolvedValue('# HELP mock metrics\n# TYPE mock gauge\nmock_metric 1');
    
    mockMetricsService.getRegistry.mockReturnValue(mockRegistry);

    const module: TestingModule = await Test.createTestingModule({
      controllers: [MetricsController],
      providers: [
        {
          provide: MetricsService,
          useValue: mockMetricsService,
        },
        {
          provide: MetricsGuard,
          useValue: { canActivate: jest.fn(() => true) },
        },
      ],
    }).compile();

    controller = module.get<MetricsController>(MetricsController);
    metricsService = module.get<MetricsService>(MetricsService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getMetrics', () => {
    it('should return metrics from registry', async () => {
      const result = await controller.getMetrics();
      
      expect(metricsService.getRegistry).toHaveBeenCalled();
      expect(mockRegistry.metrics).toHaveBeenCalled();
      expect(result).toBe('# HELP mock metrics\n# TYPE mock gauge\nmock_metric 1');
    });

    it('should handle empty registry', async () => {
      mockRegistry.metrics.mockResolvedValue('');
      mockMetricsService.getRegistry.mockReturnValue(mockRegistry);

      const result = await controller.getMetrics();
      
      expect(result).toBe('');
    });

    it('should handle multiline metrics response', async () => {
      const multilineMetrics = '# HELP http_requests_total Total requests\n# TYPE http_requests_total counter\nhttp_requests_total{method="GET",route="/",status="200"} 10\n# HELP http_request_duration_seconds Request duration\n# TYPE http_request_duration_seconds histogram\nhttp_request_duration_seconds_bucket{le="0.1"} 5';
      const lineCount = multilineMetrics.split('\n').length;
      
      mockRegistry.metrics.mockResolvedValue(multilineMetrics);
      mockMetricsService.getRegistry.mockReturnValue(mockRegistry);

      const result = await controller.getMetrics();
      
      expect(result).toBe(multilineMetrics);
      expect(result.split('\n').length).toBe(lineCount);
    });

    it('should propagate errors from registry', async () => {
      const error = new Error('Registry error');
      mockRegistry.metrics.mockRejectedValue(error);
      mockMetricsService.getRegistry.mockReturnValue(mockRegistry);

      await expect(controller.getMetrics()).rejects.toThrow(InternalServerErrorException);
    });

    it('should handle registry being undefined', async () => {
      mockMetricsService.getRegistry.mockReturnValue(undefined);

      await expect(controller.getMetrics()).rejects.toThrow(InternalServerErrorException);
    });

    it('should handle registry metrics method being undefined', async () => {
      const invalidRegistry = {};
      mockMetricsService.getRegistry.mockReturnValue(invalidRegistry);

      await expect(controller.getMetrics()).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('getContentType', () => {
    it('should return content type from registry', () => {
      const result = controller.getContentType();
      
      expect(metricsService.getRegistry).toHaveBeenCalled();
      expect(result).toEqual({ type: 'text/plain; version=0.0.4' });
    });

    it('should handle different content types', () => {
      const contentTypes = [
        'text/plain; version=0.0.4',
        'text/plain',
        'application/openmetrics-text; version=1.0.0',
      ];

      contentTypes.forEach(contentType => {
        mockRegistry.contentType = contentType;
        mockMetricsService.getRegistry.mockReturnValue(mockRegistry);

        const result = controller.getContentType();
        expect(result).toEqual({ type: contentType });
      });
    });

    it('should handle empty content type', () => {
      mockRegistry.contentType = '';
      mockMetricsService.getRegistry.mockReturnValue(mockRegistry);

      const result = controller.getContentType();
      expect(result).toEqual({ type: '' });
    });

    it('should handle registry without contentType property', () => {
      const registryWithoutContentType = {
        metrics: jest.fn(),
      };
      mockMetricsService.getRegistry.mockReturnValue(registryWithoutContentType);

      const result = controller.getContentType();
      expect(result).toEqual({ type: undefined });
    });

    it('should handle registry being undefined', () => {
      mockMetricsService.getRegistry.mockReturnValue(undefined);

      const result = controller.getContentType();
      expect(result).toEqual({ type: undefined });
    });
  });

  describe('guard integration', () => {
    it('should have MetricsGuard applied to getMetrics endpoint', () => {
      const guards = Reflect.getMetadata('__guards__', MetricsController.prototype.getMetrics);
      expect(guards).toBeDefined();
      expect(guards[0]).toBe(MetricsGuard);
    });

    it('should not have guard on getContentType endpoint', () => {
      const guards = Reflect.getMetadata('__guards__', MetricsController.prototype.getContentType);
      expect(guards).toBeUndefined();
    });
  });

  describe('error handling', () => {
    it('should handle service throwing error in getMetrics', async () => {
      mockMetricsService.getRegistry.mockImplementation(() => {
        throw new Error('Service error');
      });

      await expect(controller.getMetrics()).rejects.toThrow(InternalServerErrorException);
    });

    it('should handle service throwing error in getContentType', () => {
      mockMetricsService.getRegistry.mockImplementation(() => {
        throw new Error('Service error');
      });

      expect(() => controller.getContentType()).toThrow('Service error');
    });

    it('should handle metrics() method throwing unexpected error', async () => {
      mockRegistry.metrics.mockRejectedValue(new Error('Unexpected database error'));
      mockMetricsService.getRegistry.mockReturnValue(mockRegistry);

      await expect(controller.getMetrics()).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('real-world scenarios', () => {
    it('should handle concurrent calls to getMetrics', async () => {
      mockMetricsService.getRegistry.mockReturnValue(mockRegistry);
      
      const promises = [
        controller.getMetrics(),
        controller.getMetrics(),
        controller.getMetrics(),
      ];

      const results = await Promise.all(promises);
      
      expect(results.length).toBe(3);
      results.forEach(result => {
        expect(result).toBe('# HELP mock metrics\n# TYPE mock gauge\nmock_metric 1');
      });
      expect(mockRegistry.metrics).toHaveBeenCalledTimes(3);
    });

    it('should handle rapid succession of different endpoint calls', () => {
      mockMetricsService.getRegistry.mockReturnValue(mockRegistry);

      for (let i = 0; i < 10; i++) {
        controller.getContentType();
      }

      expect(mockMetricsService.getRegistry).toHaveBeenCalledTimes(10);
    });
  });
});

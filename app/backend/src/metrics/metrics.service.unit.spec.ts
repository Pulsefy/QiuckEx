import { Test, TestingModule } from '@nestjs/testing';
import { MetricsService } from './metrics.service';
import * as client from 'prom-client';

// Mock prom-client - define mocks first
const mockRegistry = {
  registerMetric: jest.fn(),
  metrics: jest.fn().mockResolvedValue('mock metrics'),
  contentType: 'text/plain',
};

const mockHistogram = {
  labels: jest.fn().mockReturnThis(),
  observe: jest.fn(),
};

const mockCounter = {
  labels: jest.fn().mockReturnThis(),
  inc: jest.fn(),
};

const mockGauge = {
  inc: jest.fn(),
  dec: jest.fn(),
};

// Mock implementation
jest.mock('prom-client', () => ({
  Registry: jest.fn().mockImplementation(() => mockRegistry),
  collectDefaultMetrics: jest.fn(),
  Histogram: jest.fn().mockImplementation(() => mockHistogram),
  Counter: jest.fn().mockImplementation(() => mockCounter),
  Gauge: jest.fn().mockImplementation(() => mockGauge),
}));

describe('MetricsService', () => {
  let service: MetricsService;
  let consoleErrorSpy: jest.SpyInstance;

  beforeEach(async () => {
    // Clear all mocks before each test
    jest.clearAllMocks();
    
    // Reset mock implementations
    mockHistogram.labels.mockReturnThis();
    mockCounter.labels.mockReturnThis();
    
    // Spy on console.error to prevent test output pollution
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

    const module: TestingModule = await Test.createTestingModule({
      providers: [MetricsService],
    }).compile();

    service = module.get<MetricsService>(MetricsService);
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('onModuleInit', () => {
    it('should initialize registry and metrics', () => {
      service.onModuleInit();

      expect(client.Registry).toHaveBeenCalled();
      expect(client.collectDefaultMetrics).toHaveBeenCalledWith({
        register: expect.any(Object),
      });

      expect(client.Histogram).toHaveBeenCalledWith({
        name: 'http_request_duration_seconds',
        help: 'Duration of HTTP requests in seconds',
        labelNames: ['method', 'route', 'status_code'],
        buckets: [0.1, 0.5, 1, 2, 5, 10],
      });

      expect(client.Counter).toHaveBeenCalledWith({
        name: 'http_requests_total',
        help: 'Total number of HTTP requests',
        labelNames: ['method', 'route', 'status_code'],
      });

      expect(client.Gauge).toHaveBeenCalledWith({
        name: 'http_active_connections',
        help: 'Number of active connections',
      });

      expect(mockRegistry.registerMetric).toHaveBeenCalledTimes(3);
    });

    it('should handle initialization errors gracefully', () => {
      mockRegistry.registerMetric.mockImplementationOnce(() => {
        throw new Error('Registration failed');
      });

      expect(() => service.onModuleInit()).not.toThrow();
      expect(consoleErrorSpy).toHaveBeenCalled();
      
      // Restore for other tests
      mockRegistry.registerMetric.mockReset();
    });
  });

  describe('getRegistry', () => {
    it('should return the registry instance', () => {
      service.onModuleInit();
      const registry = service.getRegistry();
      expect(registry).toBeDefined();
      expect(registry).toBe(mockRegistry);
    });

    it('should return undefined if not initialized', () => {
      const registry = service.getRegistry();
      expect(registry).toBeUndefined();
    });
  });

  describe('recordRequestDuration', () => {
    it('should record request duration and increment total counter when initialized', () => {
      service.onModuleInit();
      
      const method = 'GET';
      const route = '/test';
      const statusCode = 200;
      const duration = 0.5;

      service.recordRequestDuration(method, route, statusCode, duration);

      expect(mockHistogram.labels).toHaveBeenCalledWith(
        method,
        route,
        statusCode.toString(),
      );
      expect(mockHistogram.observe).toHaveBeenCalledWith(duration);
      expect(mockCounter.labels).toHaveBeenCalledWith(
        method,
        route,
        statusCode.toString(),
      );
      expect(mockCounter.inc).toHaveBeenCalled();
    });

    it('should handle different HTTP methods', () => {
      service.onModuleInit();
      
      const methods = ['POST', 'PUT', 'DELETE', 'PATCH'];
      
      methods.forEach(method => {
        service.recordRequestDuration(method, '/test', 200, 0.5);
        expect(mockHistogram.labels).toHaveBeenCalledWith(
          method,
          '/test',
          '200',
        );
      });
    });

    it('should handle different status codes', () => {
      service.onModuleInit();
      
      const statusCodes = [200, 201, 400, 401, 403, 404, 500];
      
      statusCodes.forEach(code => {
        service.recordRequestDuration('GET', '/test', code, 0.5);
        expect(mockHistogram.labels).toHaveBeenCalledWith(
          'GET',
          '/test',
          code.toString(),
        );
      });
    });

    it('should handle zero duration', () => {
      service.onModuleInit();
      service.recordRequestDuration('GET', '/test', 200, 0);
      expect(mockHistogram.observe).toHaveBeenCalledWith(0);
    });

    it('should handle negative duration', () => {
      service.onModuleInit();
      service.recordRequestDuration('GET', '/test', 200, -1);
      expect(mockHistogram.observe).toHaveBeenCalledWith(-1);
    });

    it('should not throw when not initialized', () => {
      expect(() => {
        service.recordRequestDuration('GET', '/test', 200, 0.5);
      }).not.toThrow();
      
      expect(mockHistogram.labels).not.toHaveBeenCalled();
    });
  });

  describe('connection management', () => {
    describe('when initialized', () => {
      beforeEach(() => {
        service.onModuleInit();
      });

      describe('incrementActiveConnections', () => {
        it('should increment active connections', () => {
          service.incrementActiveConnections();
          expect(mockGauge.inc).toHaveBeenCalled();
        });

        it('should handle multiple increments', () => {
          service.incrementActiveConnections();
          service.incrementActiveConnections();
          service.incrementActiveConnections();
          
          expect(mockGauge.inc).toHaveBeenCalledTimes(3);
        });
      });

      describe('decrementActiveConnections', () => {
        it('should decrement active connections', () => {
          service.decrementActiveConnections();
          expect(mockGauge.dec).toHaveBeenCalled();
        });

        it('should handle multiple decrements', () => {
          service.decrementActiveConnections();
          service.decrementActiveConnections();
          service.decrementActiveConnections();
          
          expect(mockGauge.dec).toHaveBeenCalledTimes(3);
        });
      });

      it('should handle increment and decrement together', () => {
        service.incrementActiveConnections();
        service.incrementActiveConnections();
        service.decrementActiveConnections();
        
        expect(mockGauge.inc).toHaveBeenCalledTimes(2);
        expect(mockGauge.dec).toHaveBeenCalledTimes(1);
      });
    });

    describe('when not initialized', () => {
      it('should not throw when incrementing', () => {
        expect(() => service.incrementActiveConnections()).not.toThrow();
        expect(mockGauge.inc).not.toHaveBeenCalled();
      });

      it('should not throw when decrementing', () => {
        expect(() => service.decrementActiveConnections()).not.toThrow();
        expect(mockGauge.dec).not.toHaveBeenCalled();
      });
    });
  });

  describe('error handling', () => {
    it('should handle when histogram throws error', () => {
      service.onModuleInit();
      
      mockHistogram.labels.mockImplementationOnce(() => {
        throw new Error('Labels error');
      });
      
      expect(() => {
        service.recordRequestDuration('GET', '/test', 200, 0.5);
      }).not.toThrow();
    });

    it('should handle when gauge throws error', () => {
      service.onModuleInit();
      
      mockGauge.inc.mockImplementationOnce(() => {
        throw new Error('Gauge error');
      });
      
      expect(() => {
        service.incrementActiveConnections();
      }).not.toThrow();
    });
  });

  describe('integration with prom-client', () => {
    it('should create metrics with correct labels', () => {
      service.onModuleInit();
      
      expect(client.Histogram).toHaveBeenCalledWith(
        expect.objectContaining({
          labelNames: ['method', 'route', 'status_code'],
        })
      );

      expect(client.Counter).toHaveBeenCalledWith(
        expect.objectContaining({
          labelNames: ['method', 'route', 'status_code'],
        })
      );
    });

    it('should have correct bucket configuration for histogram', () => {
      service.onModuleInit();
      
      expect(client.Histogram).toHaveBeenCalledWith(
        expect.objectContaining({
          buckets: [0.1, 0.5, 1, 2, 5, 10],
        })
      );
    });
  });
});

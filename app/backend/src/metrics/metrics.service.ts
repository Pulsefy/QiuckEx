import { Injectable, OnModuleInit } from '@nestjs/common';
import * as client from 'prom-client';

@Injectable()
export class MetricsService implements OnModuleInit {
  private register: client.Registry;
  private httpRequestDuration: client.Histogram<string>;
  private httpRequestTotal: client.Counter<string>;
  private activeConnections: client.Gauge<string>;
  private initialized = false;

  onModuleInit() {
    try {
      this.register = new client.Registry();
      
      client.collectDefaultMetrics({ register: this.register });

      this.httpRequestDuration = new client.Histogram({
        name: 'http_request_duration_seconds',
        help: 'Duration of HTTP requests in seconds',
        labelNames: ['method', 'route', 'status_code'],
        buckets: [0.1, 0.5, 1, 2, 5, 10],
      });

      this.httpRequestTotal = new client.Counter({
        name: 'http_requests_total',
        help: 'Total number of HTTP requests',
        labelNames: ['method', 'route', 'status_code'],
      });

      this.activeConnections = new client.Gauge({
        name: 'http_active_connections',
        help: 'Number of active connections',
      });

      this.register.registerMetric(this.httpRequestDuration);
      this.register.registerMetric(this.httpRequestTotal);
      this.register.registerMetric(this.activeConnections);
      
      this.initialized = true;
    } catch (error) {
      console.error('Failed to initialize metrics:', error);
      this.initialized = false;
    }
  }

  getRegistry(): client.Registry {
    return this.register;
  }

  recordRequestDuration(method: string, route: string, statusCode: number, duration: number) {
    if (!this.initialized || !this.httpRequestDuration || !this.httpRequestTotal) {
      return; 
    }
    
    try {
      this.httpRequestDuration.labels(method, route, statusCode.toString()).observe(duration);
      this.httpRequestTotal.labels(method, route, statusCode.toString()).inc();
    } catch (error) {
    
    }
  }

  incrementActiveConnections() {
    if (!this.initialized || !this.activeConnections) {
      return;
    }
    
    try {
      this.activeConnections.inc();
    } catch (error) {
    }
  }

  decrementActiveConnections() {
    if (!this.initialized || !this.activeConnections) {
      return;
    }
    
    try {
      this.activeConnections.dec();
    } catch (error) {
    }
  }
}


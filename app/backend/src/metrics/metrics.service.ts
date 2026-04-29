import { Injectable, OnModuleInit } from "@nestjs/common";
import * as client from "prom-client";

@Injectable()
export class MetricsService implements OnModuleInit {
  private register: client.Registry;
  private httpRequestDuration: client.Histogram<string>;
  private httpRequestTotal: client.Counter<string>;
  private rateLimitedRequestsTotal: client.Counter<string>;
  private activeConnections: client.Gauge<string>;
  private ingestionLagSeconds: client.Gauge<string>;
  private webhookRetryTotal: client.Counter<string>;
  private webhookDeliveryDuration: client.Histogram<string>;
  private externalCallDuration: client.Histogram<string>;
  private errorRate: client.Counter<string>;
  private initialized = false;

  onModuleInit() {
    try {
      this.register = new client.Registry();

      client.collectDefaultMetrics({ register: this.register });

      this.httpRequestDuration = new client.Histogram({
        name: "http_request_duration_seconds",
        help: "Duration of HTTP requests in seconds",
        labelNames: ["method", "route", "status_code"],
        buckets: [0.1, 0.5, 1, 2, 5, 10],
      });

      this.httpRequestTotal = new client.Counter({
        name: "http_requests_total",
        help: "Total number of HTTP requests",
        labelNames: ["method", "route", "status_code"],
      });

      this.rateLimitedRequestsTotal = new client.Counter({
        name: "http_rate_limited_requests_total",
        help: "Total number of requests blocked by rate limiting",
        labelNames: ["method", "route", "group", "key_type"],
      });

      this.activeConnections = new client.Gauge({
        name: "http_active_connections",
        help: "Number of active connections",
      });

      this.ingestionLagSeconds = new client.Gauge({
        name: "ingestion_lag_seconds",
        help: "Lag between current ledger and last ingested ledger in seconds",
        labelNames: ["contract_id"],
      });

      this.webhookRetryTotal = new client.Counter({
        name: "webhook_retry_total",
        help: "Total number of webhook retry attempts",
        labelNames: ["event_type", "status"],
      });

      this.webhookDeliveryDuration = new client.Histogram({
        name: "webhook_delivery_duration_seconds",
        help: "Duration of webhook delivery attempts in seconds",
        labelNames: ["event_type", "status"],
        buckets: [0.1, 0.5, 1, 2, 5, 10],
      });

      this.externalCallDuration = new client.Histogram({
        name: "external_call_duration_seconds",
        help: "Duration of external API calls in seconds",
        labelNames: ["service", "operation"],
        buckets: [0.1, 0.5, 1, 2, 5, 10, 30],
      });

      this.errorRate = new client.Counter({
        name: "error_total",
        help: "Total number of errors",
        labelNames: ["service", "error_type"],
      });

      this.register.registerMetric(this.httpRequestDuration);
      this.register.registerMetric(this.httpRequestTotal);
      this.register.registerMetric(this.rateLimitedRequestsTotal);
      this.register.registerMetric(this.activeConnections);
      this.register.registerMetric(this.ingestionLagSeconds);
      this.register.registerMetric(this.webhookRetryTotal);
      this.register.registerMetric(this.webhookDeliveryDuration);
      this.register.registerMetric(this.externalCallDuration);
      this.register.registerMetric(this.errorRate);

      this.initialized = true;
    } catch (error) {
      console.error("Failed to initialize metrics:", error);
      this.initialized = false;
    }
  }

  getRegistry(): client.Registry {
    return this.register;
  }

  recordRequestDuration(
    method: string,
    route: string,
    statusCode: number,
    duration: number,
  ) {
    if (
      !this.initialized ||
      !this.httpRequestDuration ||
      !this.httpRequestTotal
    ) {
      return;
    }

    try {
      this.httpRequestDuration
        .labels(method, route, statusCode.toString())
        .observe(duration);
      this.httpRequestTotal.labels(method, route, statusCode.toString()).inc();
    } catch (error) {}
  }

  incrementActiveConnections() {
    if (!this.initialized || !this.activeConnections) {
      return;
    }

    try {
      this.activeConnections.inc();
    } catch (error) {}
  }

  decrementActiveConnections() {
    if (!this.initialized || !this.activeConnections) {
      return;
    }

    try {
      this.activeConnections.dec();
    } catch (error) {}
  }

  recordRateLimitedRequest(
    method: string,
    route: string,
    group: string,
    keyType: string,
  ) {
    if (!this.initialized || !this.rateLimitedRequestsTotal) {
      return;
    }

    try {
      this.rateLimitedRequestsTotal.labels(method, route, group, keyType).inc();
    } catch (error) {}
  }

  recordIngestionLag(contractId: string, lagSeconds: number) {
    if (!this.initialized || !this.ingestionLagSeconds) {
      return;
    }

    try {
      this.ingestionLagSeconds.labels(contractId).set(lagSeconds);
    } catch (error) {}
  }

  recordWebhookRetry(eventType: string, status: string) {
    if (!this.initialized || !this.webhookRetryTotal) {
      return;
    }

    try {
      this.webhookRetryTotal.labels(eventType, status).inc();
    } catch (error) {}
  }

  recordWebhookDeliveryDuration(eventType: string, status: string, duration: number) {
    if (!this.initialized || !this.webhookDeliveryDuration) {
      return;
    }

    try {
      this.webhookDeliveryDuration.labels(eventType, status).observe(duration);
    } catch (error) {}
  }

  recordExternalCall(service: string, operation: string, duration: number) {
    if (!this.initialized || !this.externalCallDuration) {
      return;
    }

    try {
      this.externalCallDuration.labels(service, operation).observe(duration);
    } catch (error) {}
  }

  recordError(service: string, errorType: string) {
    if (!this.initialized || !this.errorRate) {
      return;
    }

    try {
      this.errorRate.labels(service, errorType).inc();
    } catch (error) {}
  }
}

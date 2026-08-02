import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { Request } from "express";
import { AuditService } from "../audit/audit.service";
import { MetricsService } from "../metrics/metrics.service";
import { SorobanErrorCode } from "../common/soroban-errors";
import { IndexerLagService } from "./indexer-lag.service";
import { REQUIRE_INDEXER_LAG_CHECK_KEY } from "./requires-indexer-lag-check.decorator";

@Injectable()
export class IndexerLagGuard implements CanActivate {
  private readonly logger = new Logger(IndexerLagGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly indexerLagService: IndexerLagService,
    private readonly auditService: AuditService,
    private readonly metricsService: MetricsService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const requiresCheck = this.reflector.getAllAndOverride<boolean>(
      REQUIRE_INDEXER_LAG_CHECK_KEY,
      [ctx.getHandler(), ctx.getClass()],
    );

    if (!requiresCheck) {
      return true;
    }

    const isBlocked = this.indexerLagService.isBlocked();
    if (!isBlocked) {
      return true;
    }

    const req = ctx.switchToHttp().getRequest<Request>();
    const userId = (req.headers["x-user-id"] as string | undefined)?.trim();
    const route = req.route?.path || req.path;

    await this.auditService.log(
      userId ?? "anonymous",
      "indexer_lag_guard.blocked",
      "INDEXER_LAG",
      {
        ...this.indexerLagService.getStatus(),
        method: req.method,
        path: req.path,
      },
    );

    this.metricsService.recordIndexerLagGuardBlockedRequest(
      req.method,
      route,
    );

    this.logger.warn(
      `IndexerLagGuard blocked ${req.method} ${req.path} due to indexer lag`,
    );

    const status = this.indexerLagService.getStatus();

    throw new ServiceUnavailableException({
      error: SorobanErrorCode.INDEXER_LAGGING,
      message:
        "Indexer is currently lagging behind the network. Risky operations are temporarily disabled. Please retry later.",
      details: {
        currentNetworkLedger: status.currentNetworkLedger,
        lastIndexedLedger: status.lastIndexedLedger,
        lagLedgers: status.lagLedgers,
        thresholdLedgers: status.thresholdLedgers,
      },
    });
  }
}

import { Injectable, Logger, NestMiddleware } from "@nestjs/common";
import { Request, Response, NextFunction } from "express";
import { AbuseSignalService } from "./abuse-signal.service";
import { SignalActionType, SignalOutcome } from "./abuse-signal.types";

const PAYMENT_ROUTES = new Set([
  "/payment-links/status",
  "/links/metadata",
]);

@Injectable()
export class AbuseSignalMiddleware implements NestMiddleware {
  private readonly logger = new Logger(AbuseSignalMiddleware.name);

  constructor(private readonly abuseSignalService: AbuseSignalService) {}

  use(req: Request, res: Response, next: NextFunction): void {
    if (!this.isPaymentPageRoute(req.path)) {
      next();
      return;
    }

    res.on("finish", () => {
      this.recordSignal(req, res).catch((err) =>
        this.logger.warn(`Failed to record abuse signal: ${err.message}`),
      );
    });

    next();
  }

  private isPaymentPageRoute(path: string): boolean {
    for (const route of PAYMENT_ROUTES) {
      if (path.includes(route)) return true;
    }
    return false;
  }

  private getClientIp(req: Request): string {
    const forwarded = req.headers["x-forwarded-for"];
    if (typeof forwarded === "string") {
      return forwarded.split(",")[0].trim();
    }
    const realIp = req.headers["x-real-ip"];
    if (typeof realIp === "string") return realIp;
    return req.ip ?? "0.0.0.0";
  }

  private getUserAgent(req: Request): string {
    return (req.headers["user-agent"] as string) ?? "";
  }

  private getTargetUsername(req: Request): string | undefined {
    if (req.method === "GET") {
      return (req.query.username as string) || undefined;
    }
    if (req.method === "POST" && req.body) {
      return (req.body as Record<string, unknown>)?.username as string | undefined;
    }
    return undefined;
  }

  private determineOutcome(statusCode: number): SignalOutcome {
    if (statusCode === 429) return "rate_limited";
    if (statusCode === 404) return "not_found";
    if (statusCode === 400) return "invalid_params";
    if (statusCode >= 500) return "error";
    if (statusCode < 400) return "success";
    return "error";
  }

  private determineActionType(path: string): SignalActionType {
    if (path.includes("payment-links")) return "payment_link_status";
    if (path.includes("links/metadata")) return "link_metadata";
    return "payment_link_status";
  }

  private async recordSignal(req: Request, res: Response): Promise<void> {
    const ip = this.getClientIp(req);
    const ua = this.getUserAgent(req);
    const outcome = this.determineOutcome(res.statusCode);
    const actionType = this.determineActionType(req.path);

    await this.abuseSignalService.recordSignal({
      ipAddress: ip,
      userAgent: ua,
      actionType,
      actionOutcome: outcome,
      targetUsername: this.getTargetUsername(req),
      requestMethod: req.method,
      requestPath: req.path,
      statusCode: res.statusCode,
    });
  }
}

import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from "@nestjs/common";
import { ThrottlerException } from "@nestjs/throttler";
import { Request, Response } from "express";
import { AppConfigService } from "../../config";
import { MetricsService } from "../../metrics/metrics.service";

interface ErrorResponseBody {
  success: false;
  error: {
    code: string;
    message: string | string[];
    correlationId?: string;
    fields?: unknown;
    details?: unknown;
  };
}

type ValidationExceptionPayload = {
  code: "VALIDATION_ERROR";
  message?: string;
  fields: unknown;
};

type BusinessExceptionPayload = {
  message?: string | string[];
  code?: string;
  field?: string;
};

type HttpExceptionResponse =
  | string
  | ValidationExceptionPayload
  | BusinessExceptionPayload;

@Catch()
export class GlobalHttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalHttpExceptionFilter.name);

  constructor(
    private readonly config: AppConfigService,
    private readonly metricsService?: MetricsService,
  ) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const isProduction = this.config.isProduction;

    // Extract correlation ID for traceability
    const correlationId = (request as Record<string, unknown>)[
      "correlationId"
    ] as string | undefined;

    let status: number = HttpStatus.INTERNAL_SERVER_ERROR;
    let code = "INTERNAL_SERVER_ERROR";
    let message: string | string[] = "An unexpected error occurred";
    let details: unknown = undefined;

    if (exception instanceof ThrottlerException) {
      status = HttpStatus.TOO_MANY_REQUESTS;
      code = "RATE_LIMIT_EXCEEDED";
      const retryAfterSeconds = this.getRetryAfterSeconds(response);

      message =
        retryAfterSeconds > 0
          ? `Too many requests. Retry after ${retryAfterSeconds} seconds.`
          : "Too many requests. Please try again later.";

      details = {
        retryAfterSeconds,
      };

      const reqRecord = request as Record<string, unknown>;
      const rateLimitContext =
        (reqRecord["rateLimitContext"] as
          | { group?: string; keyType?: string }
          | undefined) ?? {};

      const route = this.resolveRoute(request);

      this.metricsService?.recordRateLimitedRequest(
        request.method,
        route,
        rateLimitContext.group ?? "public",
        rateLimitContext.keyType ?? "ip",
      );
    } else if (exception instanceof HttpException) {
      status = exception.getStatus();
      const res = exception.getResponse() as HttpExceptionResponse;

      if (typeof res === "string") {
        message = res;
      } else if (typeof res === "object" && res !== null) {
        // ✅ VALIDATION ERRORS
        if ("fields" in res) {
          const validation = res as ValidationExceptionPayload;

          return response.status(status).json({
            success: false,
            error: {
              code: "VALIDATION_ERROR",
              message: validation.message ?? "Validation failed",
              fields: validation.fields ?? [],
              ...(correlationId ? { correlationId } : {}),
            },
          });
        }

        // ✅ BUSINESS ERRORS
        const business = res as BusinessExceptionPayload;

        code = business.code ?? exception.name;
        message = business.message ?? exception.message;

        if (business.field) {
          details = { field: business.field };
        }
      }
    } else if (exception instanceof Error) {
      message = isProduction ? "Internal server error" : exception.message;

      // Log the full stack for server errors
      this.logger.error(
        `Unhandled exception: ${exception.message}`,
        exception.stack,
      );
    }

    const body: ErrorResponseBody = {
      success: false,
      error: {
        code,
        message,
        ...(correlationId ? { correlationId } : {}),
        ...(details && !isProduction ? { details } : {}),
      },
    };

    response.status(status).json(body);
  }

  private getRetryAfterSeconds(response: Response): number {
    const retryAfter = response.getHeader("Retry-After");
    if (typeof retryAfter === "string") {
      const parsed = Number(retryAfter);
      if (!Number.isNaN(parsed) && parsed >= 0) return parsed;
    }

    return 0;
  }

  private resolveRoute(request: Request): string {
    const routePath = request.route?.path;
    const baseUrl = request.baseUrl ?? "";

    if (typeof routePath === "string" && routePath.length > 0) {
      return `${baseUrl}${routePath}`;
    }

    return request.path ?? request.url;
  }
}

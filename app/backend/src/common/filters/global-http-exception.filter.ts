import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from "@nestjs/common";
import { ThrottlerException } from "@nestjs/throttler";
import { Response } from "express";
import { AppConfigService } from "../../config";

interface ErrorResponseBody {
  success: false;
  error: {
    code: string;
    message: string | string[];
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
  constructor(private readonly config: AppConfigService) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const isProduction = this.config.isProduction;

    let status: number = HttpStatus.INTERNAL_SERVER_ERROR;
    let code = "INTERNAL_SERVER_ERROR";
    let message: string | string[] = "An unexpected error occurred";
    let details: unknown = undefined;

    if (exception instanceof ThrottlerException) {
      status = HttpStatus.TOO_MANY_REQUESTS;
      code = "RATE_LIMIT_EXCEEDED";
      message = "Too many requests. Please try again later.";
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
    }

    const body: ErrorResponseBody = {
      success: false,
      error: {
        code,
        message,
        ...(details && !isProduction ? { details } : {}),
      },
    };

    response.status(status).json(body);
  }
}

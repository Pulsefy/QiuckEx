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
    message: string;
    details?: unknown;
  };
}

type HttpExceptionResponse =
  | string
  | {
      message?: string | string[];
      code?: string;
      field?: string;
    };

@Catch()
export class GlobalHttpExceptionFilter implements ExceptionFilter {
  constructor(private readonly config: AppConfigService) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    const isProduction = this.config.isProduction;

    let status: number = HttpStatus.INTERNAL_SERVER_ERROR;
    let code = "INTERNAL_SERVER_ERROR";
    let message = "An unexpected error occurred";
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
        if (Array.isArray(res.message)) {
          // ValidationPipe error
          code = "VALIDATION_ERROR";
          message = "Validation failed";
          details = res.message;
        } else {
          code = res.code ?? exception.name;
          message = res.message ?? exception.message;

          if (res.field) {
            details = { field: res.field };
          }
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

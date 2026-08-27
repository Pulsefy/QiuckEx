import { applyDecorators } from "@nestjs/common";
import { ApiResponse, ApiResponseOptions } from "@nestjs/swagger";
import { ErrorEnvelopeDto } from "../dto/error-response.dto";

/**
 * Documents the canonical error envelope on a route.
 *
 * All errors in this API flow through GlobalHttpExceptionFilter and are
 * normalized to `{ code, message, fields?, traceId? }` wrapped in a
 * `{ success: false, error }` object. Use this decorator to advertise the
 * envelope for a given status code.
 */
export function ApiErrorResponse(
  status: number | "default",
  options: Omit<ApiResponseOptions, "status" | "schema" | "type"> = {},
) {
  return applyDecorators(
    ApiResponse({
      ...options,
      status: status as number,
      type: ErrorEnvelopeDto,
      description:
        options.description ??
        "Standardized error envelope { code, message, fields?, traceId? }.",
    }),
  );
}

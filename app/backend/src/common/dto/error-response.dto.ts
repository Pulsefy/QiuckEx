import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

/**
 * Canonical error envelope returned by every endpoint via
 * GlobalHttpExceptionFilter.
 *
 * Shape: { code, message, fields?, traceId? }
 */
export class ErrorResponseDto {
  @ApiProperty({
    description:
      "Stable machine-readable error code (e.g. VALIDATION_ERROR, RATE_LIMIT_EXCEEDED, INTERNAL_ERROR).",
    example: "VALIDATION_ERROR",
  })
  code: string;

  @ApiProperty({
    description: "Human-readable error message.",
    example: "Validation failed",
  })
  message: string;

  @ApiPropertyOptional({
    description:
      "Field-level validation errors (only present on VALIDATION_ERROR).",
    example: [
      {
        field: "accountId",
        errors: ["accountId must match /^G[A-Z2-7]{55}$/ regular expression"],
      },
    ],
    type: "array",
    items: {
      type: "object",
      additionalProperties: true,
    },
  })
  fields?: Array<Record<string, unknown>>;

  @ApiProperty({
    description: "Stable trace identifier for correlating requests server-side.",
    example: "b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e",
  })
  traceId: string;
}

/**
 * Error envelope for the HTTP-level `success: false` wrapper that carries the
 * canonical ErrorResponseDto. Documented so clients can introspect it.
 */
export class ErrorEnvelopeDto {
  @ApiProperty({ example: false })
  success: false;

  @ApiProperty({ type: ErrorResponseDto })
  error: ErrorResponseDto;
}

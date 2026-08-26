import {
  BadRequestException,
  CallHandler,
  ConflictException,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from "@nestjs/common";
import { Request, Response } from "express";
import { createHash } from "crypto";
import { Observable, of, throwError } from "rxjs";
import { catchError, map } from "rxjs/operators";

import { IdempotencyStore } from "./idempotency-store.service";

export const IDEMPOTENCY_KEY_HEADER = "Idempotency-Key";

/** Maximum accepted length for an idempotency key. */
export const MAX_IDEMPOTENCY_KEY_LENGTH = 128;

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Enforces `Idempotency-Key` semantics on mutating payment and link
 * endpoints (BE-109).
 *
 * - Requests without the header pass through untouched.
 * - Same key + same body after completion replays the original response
 *   (including status code) without re-executing the handler.
 * - Same key with a different body is rejected with a stable 409 conflict.
 * - A duplicate request arriving while the first is still in flight gets a
 *   stable 409 as well.
 * - Failed handlers release the key so clients can retry it.
 */
@Injectable()
export class IdempotencyInterceptor implements NestInterceptor {
  constructor(private readonly store: IdempotencyStore) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    if (context.getType() !== "http") {
      return next.handle();
    }

    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();

    if (!MUTATING_METHODS.has(req.method.toUpperCase())) {
      return next.handle();
    }

    const rawKey = req.header(IDEMPOTENCY_KEY_HEADER);
    // No header — nothing to enforce; endpoint behaves exactly as before.
    if (rawKey === undefined) {
      return next.handle();
    }

    const key = String(rawKey).trim();
    if (!key) {
      throw new BadRequestException({
        code: "IDEMPOTENCY_KEY_INVALID",
        message: "Idempotency-Key header must not be empty.",
      });
    }
    if (key.length > MAX_IDEMPOTENCY_KEY_LENGTH) {
      throw new BadRequestException({
        code: "IDEMPOTENCY_KEY_INVALID",
        message: `Idempotency-Key header must not exceed ${MAX_IDEMPOTENCY_KEY_LENGTH} characters.`,
      });
    }

    const fingerprint = this.buildFingerprint(req);
    const existing = this.store.begin(key, fingerprint);

    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        throw new ConflictException({
          code: "IDEMPOTENCY_KEY_REUSED",
          message:
            "This Idempotency-Key was already used with a different request.",
        });
      }
      if (existing.status === "PENDING") {
        throw new ConflictException({
          code: "IDEMPOTENCY_KEY_IN_PROGRESS",
          message:
            "A request with this Idempotency-Key is currently being processed. Retry later to obtain its result.",
        });
      }
      // Completed — replay the original response without re-executing.
      res.status(existing.statusCode ?? 200);
      return of(existing.responseBody);
    }

    // Capture status overrides applied while the handler runs (Nest applies
    // @HttpCode / default POST 201 when serializing the response), so replays
    // reproduce the original status code.
    let capturedStatus: number | undefined;
    const originalStatus = res.status.bind(res);
    res.status = ((code: number) => {
      capturedStatus = code;
      return originalStatus(code);
    }) as typeof res.status;

    return next.handle().pipe(
      map((body) => {
        this.store.complete(
          key,
          capturedStatus ?? res.statusCode ?? 200,
          body,
        );
        return body;
      }),
      catchError((err: unknown) => {
        // Release the key so the client can retry the same key after failure.
        this.store.release(key);
        return throwError(() => err);
      }),
    );
  }

  /**
   * Fingerprint binds a key to method + path + body, so replaying a key on a
   * different endpoint or payload can never return a mismatched response.
   */
  private buildFingerprint(req: Request): string {
    return createHash("sha256")
      .update(
        JSON.stringify({
          method: req.method.toUpperCase(),
          url: req.originalUrl,
          body: req.body ?? null,
        }),
      )
      .digest("hex");
  }
}

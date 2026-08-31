import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
} from "@nestjs/common";

import {
  buildRegistryIndex,
  EMERGENCY_CLASSIFICATION_KEY,
  EMERGENCY_ENTRYPOINT_REGISTRY,
  EmergencyStatus,
  registryKey,
} from "./emergency-entrypoint-registry";

/**
 * Stable error code surfaced to clients when an entrypoint is rejected by the
 * emergency allowlist guard.
 *
 * Clients that handle emergency-mode errors should match on this string.
 */
export const EMERGENCY_MODE_ACTIVE_CODE = "EMERGENCY_MODE_ACTIVE";

/**
 * EmergencyEntrypointAllowlistGuard
 *
 * This guard enforces the entrypoint classification declared in
 * `EMERGENCY_ENTRYPOINT_REGISTRY`. It is designed to be composed with
 * `NetworkSafetyGuard` on routes that need it, or applied globally so that
 * every route is evaluated.
 *
 * Behaviour
 * ---------
 * 1. The guard looks up the incoming request's controller class + handler
 *    method against the registry index built from
 *    `EMERGENCY_ENTRYPOINT_REGISTRY`.
 *
 * 2. If the entry has `status: 'blocked'`, the guard throws
 *    `ForbiddenException` with code `EMERGENCY_MODE_ACTIVE`.
 *
 * 3. If the entry has `status: 'allowed'`, the guard passes the request
 *    through regardless of emergency state.
 *
 * 4. If the entry is **not found in the registry at all**, the guard throws
 *    `ForbiddenException` with code `EMERGENCY_CLASSIFICATION_MISSING`. This
 *    is the fail-closed behaviour that prevents newly added entrypoints from
 *    silently bypassing the mechanism.
 *
 * Activation
 * ----------
 * The guard is *always* active at the class level but only *blocks* requests
 * when:
 *   (a) the handler is explicitly classified as 'blocked', OR
 *   (b) the handler is unclassified (fail-closed).
 *
 * A caller that is in charge of determining whether emergency mode is active
 * should only mount this guard during an actual emergency — or use the
 * `EmergencyClassification` decorator + this guard in tandem so that the
 * registry is always consulted and classification gaps are caught early in CI
 * (via the exhaustiveness spec) rather than at runtime.
 *
 * Usage
 * -----
 * Apply to individual high-risk controllers:
 *
 *   @UseGuards(NetworkSafetyGuard, EmergencyEntrypointAllowlistGuard)
 *   @Controller('transactions')
 *   export class TransactionsController { ... }
 *
 * Or register globally in AppModule for full coverage.
 */
@Injectable()
export class EmergencyEntrypointAllowlistGuard implements CanActivate {
  private readonly logger = new Logger(EmergencyEntrypointAllowlistGuard.name);

  /** Lazily built and cached index for performance. */
  private readonly registryIndex = buildRegistryIndex(
    EMERGENCY_ENTRYPOINT_REGISTRY,
  );

  canActivate(ctx: ExecutionContext): boolean {
    const handlerName = ctx.getHandler().name;
    const controllerClass = ctx.getClass() as new (
      ...args: unknown[]
    ) => object;
    const key = registryKey(controllerClass, handlerName);

    // ── 1. Check decorator-level metadata (fast path) ─────────────────────
    // If the handler has been explicitly decorated with @EmergencyClassification
    // we respect that directly without a registry lookup, giving decorator-level
    // overrides precedence over the registry.
    const decoratorMeta = Reflect.getMetadata(
      EMERGENCY_CLASSIFICATION_KEY,
      ctx.getHandler(),
    ) as { status: EmergencyStatus } | undefined;

    if (decoratorMeta) {
      if (decoratorMeta.status === "blocked") {
        this.rejectBlocked(handlerName, key);
      }
      return true;
    }

    // ── 2. Fall back to the registry index ────────────────────────────────
    const entry = this.registryIndex.get(key);

    if (!entry) {
      // Fail-closed: an unclassified entrypoint is never allowed through.
      this.logger.error(
        `EmergencyEntrypointAllowlistGuard: unclassified entrypoint "${key}" — ` +
          "add it to EMERGENCY_ENTRYPOINT_REGISTRY and decorate it with " +
          "@EmergencyClassification to resolve this.",
      );
      throw new ForbiddenException({
        code: "EMERGENCY_CLASSIFICATION_MISSING",
        error: "EMERGENCY_CLASSIFICATION_MISSING",
        entrypoint: key,
        message:
          `Entrypoint "${key}" has no emergency classification. ` +
          "Add it to EMERGENCY_ENTRYPOINT_REGISTRY with a status and rationale.",
      });
    }

    if (entry.status === "blocked") {
      this.rejectBlocked(handlerName, key);
    }

    return true;
  }

  private rejectBlocked(handlerName: string, key: string): never {
    this.logger.warn(
      `EmergencyEntrypointAllowlistGuard: blocked "${key}" — emergency mode is active.`,
    );
    throw new ForbiddenException({
      code: EMERGENCY_MODE_ACTIVE_CODE,
      error: EMERGENCY_MODE_ACTIVE_CODE,
      entrypoint: key,
      message:
        `Entrypoint "${handlerName}" is not available while emergency mode is active. ` +
        "Consult the status page or contact support.",
    });
  }
}

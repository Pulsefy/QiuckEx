/**
 * Emergency Entrypoint Allowlist — exhaustiveness & behaviour tests
 *
 * This file is the enforcement layer for SC-W8-17.  It has three goals:
 *
 *   1. EXHAUSTIVENESS — Every handler listed in EMERGENCY_ENTRYPOINT_REGISTRY
 *      actually exists on its controller prototype (no phantom entries).
 *
 *   2. DECORATOR PRESENCE — Every 'blocked' handler in the registry is
 *      decorated with @EmergencyClassification('blocked', ...) so that
 *      decorator-based tooling (e.g. Swagger, other guards) can read the
 *      classification without importing the registry.
 *
 *   3. GUARD BEHAVIOUR
 *      a. BLOCKED entries: EmergencyEntrypointAllowlistGuard throws
 *         ForbiddenException({ code: 'EMERGENCY_MODE_ACTIVE' }).
 *      b. ALLOWED entries: the guard returns true.
 *      c. UNCLASSIFIED entries: the guard throws
 *         ForbiddenException({ code: 'EMERGENCY_CLASSIFICATION_MISSING' }).
 */

import { ForbiddenException } from "@nestjs/common";
import type { ExecutionContext } from "@nestjs/common";

import {
  EMERGENCY_CLASSIFICATION_KEY,
  EMERGENCY_ENTRYPOINT_REGISTRY,
  EmergencyStatus,
  EntrypointClassification,
  registryKey,
} from "./emergency-entrypoint-registry";
import {
  EmergencyEntrypointAllowlistGuard,
  EMERGENCY_MODE_ACTIVE_CODE,
} from "./emergency-entrypoint-allowlist.guard";

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Retrieve the method descriptor from a controller prototype.
 * Returns `undefined` if the method doesn't exist (caught by test 1).
 */
function getDescriptor(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  controllerClass: new (...args: any[]) => object,
  methodName: string,
): PropertyDescriptor | undefined {
  return Object.getOwnPropertyDescriptor(controllerClass.prototype, methodName);
}

/**
 * Build a minimal NestJS ExecutionContext stub for a given controller +
 * handler.  The guard only reads `getHandler()` and `getClass()`.
 */
function makeCtx(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  controllerClass: new (...args: any[]) => object,
  methodName: string,
): ExecutionContext {
  const descriptor = getDescriptor(controllerClass, methodName);
  const handler = descriptor?.value as
    | ((...args: unknown[]) => unknown)
    | undefined;

  if (!handler) {
    throw new Error(
      `makeCtx: handler "${methodName}" not found on ${controllerClass.name}.prototype`,
    );
  }

  return {
    getHandler: () => handler,
    getClass: () => controllerClass,
    switchToHttp: () => ({ getRequest: () => ({}) }),
  } as unknown as ExecutionContext;
}

/**
 * Build an ExecutionContext for a *fake* (unregistered) handler so we can
 * test the fail-closed behaviour.
 */
function makeUnclassifiedCtx(): ExecutionContext {
  class FakeController {}
  const handler = function unclassifiedHandler() {
    return null;
  };
  Object.defineProperty(FakeController.prototype, "unclassifiedHandler", {
    value: handler,
  });

  return {
    getHandler: () => handler,
    getClass: () => FakeController,
    switchToHttp: () => ({ getRequest: () => ({}) }),
  } as unknown as ExecutionContext;
}

// ── Test suite 1: Exhaustiveness ──────────────────────────────────────────────

describe("EMERGENCY_ENTRYPOINT_REGISTRY — exhaustiveness", () => {
  it("has at least one entry (registry is not empty)", () => {
    expect(EMERGENCY_ENTRYPOINT_REGISTRY.length).toBeGreaterThan(0);
  });

  it("contains no duplicate entries (same controller + handler)", () => {
    const seen = new Set<string>();
    for (const entry of EMERGENCY_ENTRYPOINT_REGISTRY) {
      const key = registryKey(entry.controllerClass, entry.handlerName);
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }
  });

  it.each(
    EMERGENCY_ENTRYPOINT_REGISTRY.map((entry) => ({
      label: entry.label,
      controllerClass: entry.controllerClass,
      handlerName: entry.handlerName,
    })),
  )(
    '$label — handler "$handlerName" exists on controller prototype',
    ({ controllerClass, handlerName }) => {
      const descriptor = getDescriptor(controllerClass, handlerName);
      expect(descriptor?.value).toBeDefined();
    },
  );

  it.each(
    EMERGENCY_ENTRYPOINT_REGISTRY.map((entry) => ({
      label: entry.label,
      status: entry.status,
    })),
  )("$label — status is a valid EmergencyStatus value", ({ status }) => {
    const valid: EmergencyStatus[] = ["allowed", "blocked"];
    expect(valid).toContain(status);
  });

  it.each(
    EMERGENCY_ENTRYPOINT_REGISTRY.map((entry) => ({
      label: entry.label,
      rationale: entry.rationale,
    })),
  )("$label — has a non-empty rationale", ({ rationale }) => {
    expect(rationale.trim().length).toBeGreaterThan(0);
  });
});

// ── Test suite 2: Decorator presence ─────────────────────────────────────────

describe("EMERGENCY_ENTRYPOINT_REGISTRY — @EmergencyClassification decorator presence", () => {
  const blockedEntries = EMERGENCY_ENTRYPOINT_REGISTRY.filter(
    (e): e is EntrypointClassification => e.status === "blocked",
  );

  it("has at least one blocked entrypoint (registry is meaningful)", () => {
    expect(blockedEntries.length).toBeGreaterThan(0);
  });

  it.each(
    blockedEntries.map((entry) => ({
      label: entry.label,
      controllerClass: entry.controllerClass,
      handlerName: entry.handlerName,
    })),
  )(
    '$label — blocked handler has @EmergencyClassification("blocked") decorator',
    ({ controllerClass, handlerName }) => {
      const descriptor = getDescriptor(controllerClass, handlerName);
      expect(descriptor?.value).toBeDefined();

      const meta = Reflect.getMetadata(
        EMERGENCY_CLASSIFICATION_KEY,
        descriptor!.value as object,
      ) as { status: EmergencyStatus } | undefined;

      // The decorator must be present and must agree with the registry.
      expect(meta).toBeDefined();
      expect(meta!.status).toBe("blocked");
    },
  );
});

// ── Test suite 3: Guard behaviour ─────────────────────────────────────────────

describe("EmergencyEntrypointAllowlistGuard", () => {
  const guard = new EmergencyEntrypointAllowlistGuard();

  // ── 3a. Blocked entries reject with the documented error code ──────────────

  const blockedEntries = EMERGENCY_ENTRYPOINT_REGISTRY.filter(
    (e) => e.status === "blocked",
  );

  describe("blocked entrypoints", () => {
    it.each(
      blockedEntries.map((entry) => ({
        label: entry.label,
        controllerClass: entry.controllerClass,
        handlerName: entry.handlerName,
      })),
    )(
      "$label — guard throws ForbiddenException with code EMERGENCY_MODE_ACTIVE",
      ({ controllerClass, handlerName }) => {
        const ctx = makeCtx(controllerClass, handlerName);

        expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);

        try {
          guard.canActivate(ctx);
        } catch (err) {
          const response = (err as ForbiddenException).getResponse() as Record<
            string,
            unknown
          >;
          expect(response.code).toBe(EMERGENCY_MODE_ACTIVE_CODE);
          expect(response.error).toBe(EMERGENCY_MODE_ACTIVE_CODE);
          expect(typeof response.message).toBe("string");
          expect((response.message as string).length).toBeGreaterThan(0);
        }
      },
    );
  });

  // ── 3b. Allowed entries pass through ──────────────────────────────────────

  const allowedEntries = EMERGENCY_ENTRYPOINT_REGISTRY.filter(
    (e) => e.status === "allowed",
  );

  describe("allowed entrypoints", () => {
    it("has at least one allowed entrypoint", () => {
      expect(allowedEntries.length).toBeGreaterThan(0);
    });

    it.each(
      allowedEntries.map((entry) => ({
        label: entry.label,
        controllerClass: entry.controllerClass,
        handlerName: entry.handlerName,
      })),
    )("$label — guard returns true", ({ controllerClass, handlerName }) => {
      const ctx = makeCtx(controllerClass, handlerName);
      expect(guard.canActivate(ctx)).toBe(true);
    });
  });

  // ── 3c. Unclassified entrypoints fail closed ───────────────────────────────

  describe("unclassified entrypoints (fail-closed)", () => {
    it("throws ForbiddenException with code EMERGENCY_CLASSIFICATION_MISSING", () => {
      const ctx = makeUnclassifiedCtx();

      expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);

      try {
        guard.canActivate(ctx);
      } catch (err) {
        const response = (err as ForbiddenException).getResponse() as Record<
          string,
          unknown
        >;
        expect(response.code).toBe("EMERGENCY_CLASSIFICATION_MISSING");
        expect(response.error).toBe("EMERGENCY_CLASSIFICATION_MISSING");
        expect(typeof response.entrypoint).toBe("string");
        expect(typeof response.message).toBe("string");
      }
    });
  });
});

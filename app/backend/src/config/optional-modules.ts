/**
 * Explicit selection of the optional backend modules (#1061).
 *
 * AppModule used to decide whether to load ReconciliationModule,
 * NotificationsModule and DeveloperModule by checking whether SUPABASE_URL
 * contained "localhost" / "127.0.0.1", inside a catch-all try/catch that
 * re-added all three on any error. Contributors on a local Supabase could not
 * opt in, and the skip was not reliably reproducible.
 *
 * Inclusion is now driven only by these env flags (default: enabled). Values
 * are validated: anything other than true/false stops startup instead of
 * silently changing which modules load. SUPABASE_URL plays no part.
 *
 * ReconciliationModule and NotificationsModule are also imported directly by
 * modules that always load (see OPTIONAL_MODULE_DEPENDENTS), so Nest starts
 * them regardless of AppModule. Setting their flag to false therefore cannot be
 * honoured yet, and is rejected with an explanation rather than ignored.
 * DeveloperModule is only imported by AppModule and can be switched off.
 */

export const OPTIONAL_MODULE_FLAGS = {
  reconciliation: "ENABLE_RECONCILIATION_MODULE",
  notifications: "ENABLE_NOTIFICATIONS_MODULE",
  developer: "ENABLE_DEVELOPER_MODULE",
} as const;

export type OptionalModuleName = keyof typeof OPTIONAL_MODULE_FLAGS;

export type OptionalModuleSelection = Record<OptionalModuleName, boolean>;

/**
 * Always-loaded modules that import an optional module themselves. While this
 * list is non-empty for a module, it cannot be disabled from AppModule alone.
 * optional-modules.unit.spec.ts checks this list against the module files.
 */
export const OPTIONAL_MODULE_DEPENDENTS: Record<OptionalModuleName, readonly string[]> = {
  reconciliation: ["JobQueueModule", "FiatRampsModule"],
  notifications: ["JobQueueModule", "OperationsModule"],
  developer: [],
};

const MODULE_CLASS_NAMES: Record<OptionalModuleName, string> = {
  reconciliation: "ReconciliationModule",
  notifications: "NotificationsModule",
  developer: "DeveloperModule",
};

export class OptionalModuleConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OptionalModuleConfigError";
  }
}

/** Unset means enabled; otherwise only "true" / "false" (any case) are valid. */
export function parseModuleFlag(flag: string, raw: string | undefined): boolean {
  if (raw === undefined) {
    return true;
  }

  const value = raw.trim().toLowerCase();
  if (value === "true") return true;
  if (value === "false") return false;

  throw new OptionalModuleConfigError(
    `Invalid ${flag}="${raw}". Use "true" or "false" (or leave it unset to enable the module).`,
  );
}

/** Resolve which optional modules AppModule should import. Throws on bad config. */
export function resolveOptionalModules(
  env: NodeJS.ProcessEnv = process.env,
): OptionalModuleSelection {
  const selection = {} as OptionalModuleSelection;

  for (const name of Object.keys(OPTIONAL_MODULE_FLAGS) as OptionalModuleName[]) {
    const flag = OPTIONAL_MODULE_FLAGS[name];
    const enabled = parseModuleFlag(flag, env[flag]);
    const dependents = OPTIONAL_MODULE_DEPENDENTS[name];

    if (!enabled && dependents.length > 0) {
      throw new OptionalModuleConfigError(
        `${flag}=false cannot be honoured: ${MODULE_CLASS_NAMES[name]} is also imported by ` +
          `${dependents.join(", ")}, which always load, so it would still start. ` +
          `Leave ${flag} unset or set it to true.`,
      );
    }

    selection[name] = enabled;
  }

  return selection;
}

import { readFileSync } from "fs";
import { join } from "path";

import { envSchema } from "./env.schema";
import {
  OPTIONAL_MODULE_DEPENDENTS,
  OPTIONAL_MODULE_FLAGS,
  OptionalModuleConfigError,
  parseModuleFlag,
  resolveOptionalModules,
} from "./optional-modules";

const LOCAL_SUPABASE = "http://127.0.0.1:54321";
const ALL_ENABLED = { reconciliation: true, notifications: true, developer: true };

describe("resolveOptionalModules (#1061)", () => {
  it("enables every optional module when no flag is set", () => {
    expect(resolveOptionalModules({})).toEqual(ALL_ENABLED);
  });

  it.each([
    ["localhost", "http://localhost:54321"],
    ["127.0.0.1", LOCAL_SUPABASE],
    ["hosted", "https://project.supabase.co"],
  ])("ignores SUPABASE_URL (%s)", (_label, url) => {
    expect(resolveOptionalModules({ SUPABASE_URL: url })).toEqual(ALL_ENABLED);
  });

  it("enables every module explicitly against a local Supabase", () => {
    expect(
      resolveOptionalModules({
        SUPABASE_URL: LOCAL_SUPABASE,
        ENABLE_RECONCILIATION_MODULE: "true",
        ENABLE_NOTIFICATIONS_MODULE: "true",
        ENABLE_DEVELOPER_MODULE: "true",
      }),
    ).toEqual(ALL_ENABLED);
  });

  it("lets DeveloperModule be switched off", () => {
    expect(resolveOptionalModules({ ENABLE_DEVELOPER_MODULE: "false" })).toEqual({
      ...ALL_ENABLED,
      developer: false,
    });
  });

  it.each(["ENABLE_RECONCILIATION_MODULE", "ENABLE_NOTIFICATIONS_MODULE"])(
    "rejects %s=false instead of pretending the module is off",
    (flag) => {
      expect(() => resolveOptionalModules({ [flag]: "false" })).toThrow(OptionalModuleConfigError);
      expect(() => resolveOptionalModules({ [flag]: "false" })).toThrow(/cannot be honoured/);
    },
  );

  it.each(["yes", "1", "", "enabled", "flase"])("rejects the invalid value %p", (value) => {
    expect(() => resolveOptionalModules({ ENABLE_DEVELOPER_MODULE: value })).toThrow(
      /Invalid ENABLE_DEVELOPER_MODULE/,
    );
  });

  it("accepts true/false in any case and with surrounding spaces", () => {
    expect(parseModuleFlag("F", " TRUE ")).toBe(true);
    expect(parseModuleFlag("F", "False")).toBe(false);
    expect(parseModuleFlag("F", undefined)).toBe(true);
  });

  it("resolves every module as enabled for the current process environment", () => {
    // The dedicated CI step runs this with all three flags set to "true".
    expect(resolveOptionalModules(process.env)).toEqual(ALL_ENABLED);
  });
});

describe("env schema for optional module flags (#1061)", () => {
  const base = {
    SUPABASE_URL: LOCAL_SUPABASE,
    SUPABASE_ANON_KEY: "local-anon-key",
    NETWORK: "testnet",
  };

  it("defaults every flag to true", () => {
    const { value } = envSchema.validate(base, { allowUnknown: true });
    for (const flag of Object.values(OPTIONAL_MODULE_FLAGS)) {
      expect(value[flag]).toBe(true);
    }
  });

  it("rejects a non-boolean flag", () => {
    const { error } = envSchema.validate(
      { ...base, ENABLE_DEVELOPER_MODULE: "sometimes" },
      { allowUnknown: true },
    );
    expect(error?.message).toContain("ENABLE_DEVELOPER_MODULE");
  });
});

describe("OPTIONAL_MODULE_DEPENDENTS stays accurate (#1061)", () => {
  const moduleFiles: Record<string, string> = {
    JobQueueModule: "job-queue/job-queue.module.ts",
    FiatRampsModule: "fiat-ramps/fiat-ramps.module.ts",
    OperationsModule: "operations/operations.module.ts",
  };
  const classNames = {
    reconciliation: "ReconciliationModule",
    notifications: "NotificationsModule",
  } as const;

  it.each(Object.entries(classNames))(
    "%s is still imported by every listed always-on module",
    (name, className) => {
      const dependents = OPTIONAL_MODULE_DEPENDENTS[name as keyof typeof classNames];
      for (const dependent of dependents) {
        const source = readFileSync(join(__dirname, "..", moduleFiles[dependent]), "utf8");
        // If this fails, the dependency was removed: update OPTIONAL_MODULE_DEPENDENTS
        // so the module's ENABLE_* flag can be set to false.
        expect(source).toContain(className);
      }
    },
  );
});

import { MODULE_METADATA } from "@nestjs/common/constants";

/**
 * #1061: AppModule's real import list, built with SUPABASE_URL pointing at a
 * local Supabase instance — the setup that used to silently skip these
 * modules. Loads app.module in isolation so each case sees its own env.
 */
const LOCAL_SUPABASE = "http://127.0.0.1:54321";
const OPTIONAL = ["ReconciliationModule", "NotificationsModule", "DeveloperModule"];
const FLAGS = [
  "ENABLE_RECONCILIATION_MODULE",
  "ENABLE_NOTIFICATIONS_MODULE",
  "ENABLE_DEVELOPER_MODULE",
];

async function appModuleImports(env: Record<string, string>): Promise<string[]> {
  const saved = { ...process.env };
  Object.assign(process.env, { SUPABASE_URL: LOCAL_SUPABASE }, env);
  try {
    let imports: unknown[] = [];
    await jest.isolateModulesAsync(async () => {
      const { AppModule } = await import("../app.module");
      imports = Reflect.getMetadata(MODULE_METADATA.IMPORTS, AppModule) ?? [];
    });
    return imports.map((entry) => (entry as { name?: string })?.name ?? "");
  } finally {
    for (const key of Object.keys(process.env)) {
      if (!(key in saved)) delete process.env[key];
    }
    Object.assign(process.env, saved);
  }
}

describe("AppModule optional modules against a local Supabase (#1061)", () => {
  it("imports Reconciliation, Notifications and Developer when enabled", async () => {
    const names = await appModuleImports(Object.fromEntries(FLAGS.map((f) => [f, "true"])));
    expect(names).toEqual(expect.arrayContaining(OPTIONAL));
  }, 180000);

  it("leaves out DeveloperModule only when its flag is false", async () => {
    const names = await appModuleImports({ ENABLE_DEVELOPER_MODULE: "false" });
    expect(names).not.toContain("DeveloperModule");
    expect(names).toEqual(expect.arrayContaining(["ReconciliationModule", "NotificationsModule"]));
  }, 180000);
});

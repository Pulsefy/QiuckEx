import { FeatureFlags } from "@/components/admin/FeatureFlags";
import { SystemHealth } from "@/components/admin/SystemHealth";
import { AuditLogs } from "@/components/admin/AuditLogs";
import { TestnetHealthConsole } from "@/components/admin/health-console/TestnetHealthConsole";

export default function AdminPage() {
  return (
    <div className="mx-auto w-full max-w-[1400px] space-y-8 px-1">
      <section aria-label="Testnet Health Console">
        <TestnetHealthConsole />
      </section>

      <div className="border-t border-border pt-2">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <FeatureFlags />
          <SystemHealth />
        </div>
        <div className="mt-6">
          <AuditLogs />
        </div>
      </div>
    </div>
  );
}

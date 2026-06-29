import { AuditLogs } from "@/components/admin/AuditLogs";
import { FeatureFlags } from "@/components/admin/FeatureFlags";
import { SystemHealth } from "@/components/admin/SystemHealth";
import { TestnetHealthConsole } from "@/components/admin/TestnetHealthConsole";

export default function AdminPage() {
  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <TestnetHealthConsole />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <FeatureFlags />
        <SystemHealth />
      </div>
      <AuditLogs />
    </div>
  );
}

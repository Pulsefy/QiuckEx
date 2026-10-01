import { AuditLogs } from "@/components/admin/AuditLogs";
import { FeatureFlags } from "@/components/admin/FeatureFlags";
import { SystemHealth } from "@/components/admin/SystemHealth";
import { TestnetHealthConsole } from "@/components/admin/TestnetHealthConsole";

export default function AdminPage() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <TestnetHealthConsole />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <FeatureFlags />
        <SystemHealth />
      </div>
      <AuditLogs />
    </div>
  );
}

import { FeatureFlags } from "@/components/admin/FeatureFlags";
import { SystemHealth } from "@/components/admin/SystemHealth";
import { AuditLogs } from "@/components/admin/AuditLogs";
import { TestnetHealth } from "@/components/admin/TestnetHealth";

export default function AdminPage() {
  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <FeatureFlags />
        <SystemHealth />
      </div>
      <div className="mt-6">
        <TestnetHealth />
      </div>
      <AuditLogs />
    </div>
  );
}

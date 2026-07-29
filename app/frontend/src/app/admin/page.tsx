"use client";

import { useState } from "react";
import { FeatureFlags } from "@/components/admin/FeatureFlags";
import { SystemHealth } from "@/components/admin/SystemHealth";
import { AuditLogs } from "@/components/admin/AuditLogs";
import { TestnetHealthConsole } from "@/components/admin/TestnetHealthConsole";
import { Activity, FileText, Shield, Stethoscope } from "lucide-react";

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState<"testnet" | "system" | "audit">("testnet");

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Admin Tab Navigation */}
      <div className="flex items-center gap-2 border-b border-border pb-3">
        <button
          onClick={() => setActiveTab("testnet")}
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-colors ${
            activeTab === "testnet"
              ? "bg-brand text-brand-foreground shadow-xs"
              : "text-subtle hover:bg-surface hover:text-foreground"
          }`}
        >
          <Stethoscope className="h-4 w-4" />
          Testnet Health Console
        </button>
        <button
          onClick={() => setActiveTab("system")}
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-colors ${
            activeTab === "system"
              ? "bg-brand text-brand-foreground shadow-xs"
              : "text-subtle hover:bg-surface hover:text-foreground"
          }`}
        >
          <Shield className="h-4 w-4" />
          Safety & System Controls
        </button>
        <button
          onClick={() => setActiveTab("audit")}
          className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-colors ${
            activeTab === "audit"
              ? "bg-brand text-brand-foreground shadow-xs"
              : "text-subtle hover:bg-surface hover:text-foreground"
          }`}
        >
          <FileText className="h-4 w-4" />
          Audit Logs
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === "testnet" && <TestnetHealthConsole />}

      {activeTab === "system" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <FeatureFlags />
          <SystemHealth />
        </div>
      )}

      {activeTab === "audit" && <AuditLogs />}
    </div>
  );
}


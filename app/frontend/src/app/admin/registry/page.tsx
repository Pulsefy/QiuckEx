import Link from "next/link";

import { DeploymentDiagnosticsPanel } from "@/components/DeploymentDiagnosticsPanel";

async function fetchRegistry() {
  try {
    const res = await fetch(`${process.env.NEXT_PUBLIC_QUICKEX_API_URL ?? "http://localhost:4000"}/admin/registry`, { cache: "no-store" });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export default async function RegistryPage() {
  const data = await fetchRegistry();

  const entries: { id: string; name?: string; address?: string }[] = data?.entries ?? [];

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <DeploymentDiagnosticsPanel />
        <section className="bg-card p-6 rounded-lg border border-border">
          <h2 className="text-lg font-semibold mb-3">Contract Registry</h2>
          <p className="text-sm text-subtle mb-4">Version: {data?.version ?? "unknown"}</p>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-subtle">
              <thead className="text-xs text-muted uppercase bg-background border-b border-border">
                <tr>
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Address</th>
                  <th className="px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.id} className="border-b border-border last:border-0 hover:bg-background">
                    <td className="px-4 py-3 font-mono text-foreground">{e.id}</td>
                    <td className="px-4 py-3">{e.name ?? "—"}</td>
                    <td className="px-4 py-3 font-mono">{e.address ?? "—"}</td>
                    <td className="px-4 py-3">
                      <Link href={`/admin/registry/${encodeURIComponent(e.id)}`} className="text-xs text-brand font-semibold">View</Link>
                    </td>
                  </tr>
                ))}
                {entries.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-subtle">No registry entries found.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}

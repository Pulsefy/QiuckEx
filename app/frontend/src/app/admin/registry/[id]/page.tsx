import { notFound } from "next/navigation";

async function fetchEntry(id: string) {
  try {
    const res = await fetch(`${process.env.NEXT_PUBLIC_QUICKEX_API_URL ?? "http://localhost:4000"}/admin/registry/${encodeURIComponent(id)}`, { cache: "no-store" });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export default async function RegistryEntryPage({ params }: { params: { id: string } }) {
  const entry = await fetchEntry(params.id);
  if (!entry) return notFound();

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <section className="bg-card p-6 rounded-lg border border-border">
        <h1 className="text-xl font-bold mb-2">Registry Entry: {params.id}</h1>
        <p className="text-sm text-subtle mb-4">Name: {entry.name ?? "—"}</p>
        <p className="text-sm font-mono mb-4">Address: {entry.address ?? "—"}</p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <a href={`/dashboard?filter=contract:${encodeURIComponent(params.id)}`} className="block text-center py-3 px-4 rounded-lg bg-surface border border-border text-sm font-semibold">Transactions</a>
          <a href={`/webhooks?filter=contract:${encodeURIComponent(params.id)}`} className="block text-center py-3 px-4 rounded-lg bg-surface border border-border text-sm font-semibold">Webhook logs</a>
          <a href={`https://stellar.expert/explorer/testnet/account/${encodeURIComponent(entry.address)}`} target="_blank" rel="noreferrer" className="block text-center py-3 px-4 rounded-lg bg-surface border border-border text-sm font-semibold">Stellar Explorer</a>
        </div>
      </section>
    </div>
  );
}

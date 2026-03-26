import { NetworkBadge } from "@/components/NetworkBadge";
import Link from "next/link";

export default function Settings() {
  return (
    <div className="relative min-h-screen text-white selection:bg-indigo-500/30 overflow-x-hidden">
      {/* <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px]" />
      <div className="fixed bottom-[-20%] right-[-30%] w-[50%] h-[50%] bg-purple-500/5 blur-[100px]" /> */}
      <div className="max-w-5xl mx-auto pt-8">
        <h1 className="text-4xl font-black mb-6">Settings</h1>

        <nav className="flex gap-3 mb-8">
          <Link
            href="/settings"
            className="px-4 py-2 rounded-xl border border-white/10 bg-white/10 text-sm font-semibold hover:bg-white/20"
          >
            General
          </Link>
          <Link
            href="/settings/developer"
            className="px-4 py-2 rounded-xl border border-white/10 text-sm font-semibold hover:bg-white/5"
          >
            Developer
          </Link>
        </nav>

        <section className="p-6 rounded-3xl bg-neutral-900/40 border border-white/5">
          <h2 className="text-xl font-bold mb-4">General settings</h2>
          <p className="text-neutral-300">Coming soon...</p>
        </section>
      </div>
    </div>
  );
}

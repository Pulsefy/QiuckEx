export default function DashboardLoading() {
  return (
    <div className="min-h-screen text-white selection:bg-indigo-500/30">
      <div className="space-y-10">
        <div className="h-8 w-1/4 rounded-full bg-white/5 animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {Array.from({ length: 3 }).map((_, idx) => (
            <div key={idx} className="h-44 rounded-3xl bg-white/5 border border-white/5 animate-pulse" />
          ))}
        </div>
        <div className="h-[420px] rounded-3xl bg-white/5 border border-white/5 animate-pulse" />
        <div className="h-96 rounded-3xl bg-white/5 border border-white/5 animate-pulse" />
      </div>
    </div>
  );
}


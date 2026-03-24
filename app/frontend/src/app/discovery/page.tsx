"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { MOCK_USERS, User } from "@/lib/mockData";

export default function DiscoveryPage() {
  const [isLoading, setIsLoading] = useState(true);
  const [trending, setTrending] = useState<User[]>([]);
  const [recent, setRecent] = useState<User[]>([]);

  useEffect(() => {
    // Simulate network latency for smooth skeleton experience
    const timer = setTimeout(() => {
      setTrending(MOCK_USERS.filter(u => u.isTrending));
      setRecent(MOCK_USERS.filter(u => u.isRecentlyActive));
      setIsLoading(false);
    }, 1500);

    return () => clearTimeout(timer);
  }, []);

  const UserCard = ({ user }: { user: User }) => (
    <Link href={`/profile/${user.username}`} className="block group">
      <div className="p-6 rounded-3xl bg-neutral-900/40 border border-white/5 hover:border-indigo-500/30 hover:bg-neutral-900/80 transition-all h-full flex flex-col shadow-lg shadow-black/20 group-hover:shadow-indigo-500/10">
        <div className="flex items-start justify-between mb-5">
          <div className={`w-14 h-14 rounded-2xl flex items-center justify-center font-bold text-2xl shadow-inner ${user.avatarColor}`}>
            {user.name.charAt(0)}
          </div>
          <div className="flex flex-col items-end">
            <span className="text-xs font-semibold text-neutral-400 bg-black/50 px-3 py-1.5 rounded-full border border-white/5">
              {Number(user.followers).toLocaleString()} followers
            </span>
          </div>
        </div>
        <h3 className="text-lg font-bold text-white group-hover:text-indigo-400 transition-colors">{user.name}</h3>
        <p className="text-sm text-indigo-300/80 mb-4 tracking-tight">@{user.username}</p>
        <p className="text-sm text-neutral-400 flex-1 leading-relaxed">{user.bio}</p>
        
        <div className="mt-6 pt-4 border-t border-white/5 flex items-center justify-between text-xs text-neutral-500 font-medium group-hover:text-indigo-400 transition-colors">
          <span>View Profile</span>
          <span>→</span>
        </div>
      </div>
    </Link>
  );

  const SkeletonCard = () => (
    <div className="p-6 rounded-3xl bg-neutral-900/20 border border-white/5 h-full flex flex-col animate-pulse">
      <div className="flex items-start justify-between mb-5">
        <div className="w-14 h-14 rounded-2xl bg-white/10"></div>
        <div className="w-24 h-7 rounded-full bg-white/5"></div>
      </div>
      <div className="w-2/3 h-5 rounded bg-white/10 mb-2 mt-1"></div>
      <div className="w-1/3 h-4 rounded bg-white/5 mb-5"></div>
      <div className="w-full h-3 rounded bg-white/5 mb-2"></div>
      <div className="w-4/5 h-3 rounded bg-white/5 mb-2"></div>
      <div className="w-1/2 h-3 rounded bg-white/5"></div>
      
      <div className="mt-auto pt-4 border-t border-white/5 flex items-center justify-between">
        <div className="w-1/4 h-3 rounded bg-white/5"></div>
        <div className="w-4 h-4 rounded bg-white/5"></div>
      </div>
    </div>
  );

  return (
    <div className="max-w-6xl mx-auto space-y-20 py-8 selection:bg-indigo-500/30">
      <header className="space-y-6 text-center max-w-3xl mx-auto">
        <div className="w-16 h-16 bg-indigo-500/10 rounded-3xl flex items-center justify-center mx-auto mb-8 border border-indigo-500/20 shadow-xl shadow-indigo-500/10">
          <span className="text-3xl">🔭</span>
        </div>
        <h1 className="text-5xl md:text-6xl font-black tracking-tighter">
          Discover <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">QuickEx</span>
        </h1>
        <p className="text-xl text-neutral-400 leading-relaxed">
          Find public profiles, connect with trending creators, and effortlessly send payments to active members of the community.
        </p>
      </header>

      <section className="space-y-8">
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-bold flex items-center gap-3">
            <span className="text-orange-500 text-3xl drop-shadow-[0_0_15px_rgba(249,115,22,0.5)]">🔥</span> Trending Profiles
          </h2>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {isLoading 
            ? [...Array(4)].map((_, i) => <SkeletonCard key={`trending-skeleton-${i}`} />)
            : trending.map(user => <UserCard key={`trending-${user.id}`} user={user} />)
          }
        </div>
      </section>

      <section className="space-y-8">
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-bold flex items-center gap-3">
            <span className="text-emerald-500 text-3xl drop-shadow-[0_0_15px_rgba(16,185,129,0.5)]">✨</span> Recently Active
          </h2>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {isLoading 
            ? [...Array(4)].map((_, i) => <SkeletonCard key={`recent-skeleton-${i}`} />)
            : recent.map(user => <UserCard key={`recent-${user.id}`} user={user} />)
          }
        </div>
      </section>

      {/* Empty State / Join Community CTA */}
      {!isLoading && (
        <section className="mt-32 p-12 rounded-3xl bg-gradient-to-br from-indigo-900/40 to-cyan-900/20 border border-white/10 text-center space-y-6 relative overflow-hidden shadow-2xl shadow-indigo-500/5 group hover:border-white/20 transition-all">
          <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 mix-blend-overlay pointer-events-none"></div>
          <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/20 rounded-full blur-3xl -tralsate-y-1/2 translate-x-1/2"></div>
          <div className="absolute bottom-0 left-0 w-64 h-64 bg-indigo-500/20 rounded-full blur-3xl translate-y-1/2 -translate-x-1/2"></div>
          
          <h3 className="text-4xl font-bold relative z-10 tracking-tight">Want to get featured?</h3>
          <p className="text-lg text-neutral-300 max-w-xl mx-auto relative z-10">
            Create your QuickEx profile, share your link, and start receiving payments to appear on the Discovery page.
          </p>
          <div className="relative z-10 pt-8">
            <Link href="/generator" className="inline-block px-10 py-4 bg-white text-black font-bold rounded-2xl hover:bg-neutral-200 transition-all hover:scale-105 active:scale-95 shadow-xl shadow-white/10">
              Claim Your Username
            </Link>
          </div>
        </section>
      )}
    </div>
  );
}

"use client";

import { useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { NetworkBadge } from "@/components/NetworkBadge";
import { fetchAnalytics } from "@/hooks/analyticsApi";
import { fetchListings } from "@/hooks/marketplaceApi";
import '@/lib/i18n';
import { useTranslation } from 'react-i18next';

export default function Home() {
  const router = useRouter();
  const { t } = useTranslation();

  useEffect(() => {
    const handlePrefetch = () => {
      router.prefetch("/dashboard");
      router.prefetch("/marketplace");
      fetchListings();
      fetchAnalytics("30d");
    };
    const id = window.setTimeout(handlePrefetch, 250);
    return () => window.clearTimeout(id);
  }, [router]);

  return (
    <div className="selection:bg-indigo-500/30">
      <NetworkBadge />
      <section className="pt-20 md:pt-32 pb-32">
        <div className="max-w-3xl">
          <h1 className="text-6xl md:text-7xl font-bold tracking-tighter mb-8 bg-gradient-to-br from-foreground to-subtle bg-clip-text text-transparent leading-tight">
            {t('heroTitle')}
          </h1>
          <p className="text-xl text-subtle mb-12 leading-relaxed max-w-xl">
            {t('heroSubtitle')}
          </p>
          <div className="flex flex-col sm:flex-row gap-4">
            <Link
              href="/generator"
              className="px-8 py-4 bg-card text-foreground font-bold rounded-xl hover:bg-surface-strong transition-all text-center shadow-xl shadow-white/5"
            >
              {t('generateLink')}
            </Link>
            <Link
              href="/dashboard"
              className="px-8 py-4 bg-card text-foreground font-bold rounded-xl hover:bg-surface-strong transition-all border border-border-strong text-center"
            >
              {t('goToDashboard')}
            </Link>
          </div>
        </div>
        <div className="grid md:grid-cols-3 gap-8 mt-32 md:mt-48">
          <div className="p-8 rounded-3xl bg-card/50 border border-border hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition">
              <span className="text-2xl">👤</span>
            </div>
            <h3 className="text-xl font-bold mb-4">{t('shareableUsernames')}</h3>
            <p className="text-subtle">{t('shareableUsernamesDesc')}</p>
          </div>
          <div className="p-8 rounded-3xl bg-card/50 border border-border hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition">
              <span className="text-2xl">🛡️</span>
            </div>
            <h3 className="text-xl font-bold mb-4">{t('shieldedTransactions')}</h3>
            <p className="text-subtle">{t('shieldedTransactionsDesc')}</p>
          </div>
          <div className="p-8 rounded-3xl bg-card/50 border border-border hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition">
              <span className="text-2xl">⚡</span>
            </div>
            <h3 className="text-xl font-bold mb-4">{t('instantPayments')}</h3>
            <p className="text-subtle">{t('instantPaymentsDesc')}</p>
          </div>
        </div>
      </section>
    </div>
  );
}
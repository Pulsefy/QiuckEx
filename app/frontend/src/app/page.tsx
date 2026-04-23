"use client";

import { NetworkBadge } from "@/components/NetworkBadge";
import Link from "next/link";
import '@/lib/i18n';
import { useTranslation } from 'react-i18next';

export default function Home() {
  const { t } = useTranslation();

  return (
    <div className="selection:bg-indigo-500/30">
      <NetworkBadge />

      <section className="pt-20 md:pt-32 pb-32">
        <div className="max-w-3xl">
          <h1 className="text-6xl md:text-7xl font-bold tracking-tighter mb-8 bg-gradient-to-br from-white to-neutral-500 bg-clip-text text-transparent leading-tight">
            {t('heroTitle')}
          </h1>

          <p className="text-xl text-neutral-400 mb-12 leading-relaxed max-w-xl">
            {t('heroSubtitle')}
          </p>

          <div className="flex flex-col sm:flex-row gap-4">
            <Link
              href="/generator"
              className="px-8 py-4 bg-white text-black font-bold rounded-xl hover:bg-neutral-200 transition-all text-center shadow-xl shadow-white/5"
            >
              {t('generateLink')}
            </Link>

            <Link
              href="/dashboard"
              className="px-8 py-4 bg-neutral-900 text-white font-bold rounded-xl hover:bg-neutral-800 transition-all border border-white/10 text-center"
            >
              {t('goToDashboard')}
            </Link>
          </div>
        </div>

        <div className="grid md:grid-cols-3 gap-8 mt-32 md:mt-48">
          <div className="p-8 rounded-3xl bg-neutral-900/50 border border-white/5 hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition">
              <span className="text-2xl">👤</span>
            </div>
            <h3 className="text-xl font-bold mb-4">{t('shareableUsernames')}</h3>
            <p className="text-neutral-400">
              {t('shareableUsernamesDesc')}
            </p>
          </div>

          <div className="p-8 rounded-3xl bg-neutral-900/50 border border-white/5 hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition">
              <span className="text-2xl">🛡️</span>
            </div>
            <h3 className="text-xl font-bold mb-4">{t('shieldedTransactions')}</h3>
            <p className="text-neutral-400">
              {t('shieldedTransactionsDesc')}
            </p>
          </div>

          <div className="p-8 rounded-3xl bg-neutral-900/50 border border-white/5 hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition">
              <span className="text-2xl">⚡</span>
            </div>
            <h3 className="text-xl font-bold mb-4">{t('instantPayments')}</h3>
            <p className="text-neutral-400">
              {t('instantPaymentsDesc')}
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

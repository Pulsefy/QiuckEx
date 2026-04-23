'use client';

import Link from "next/link";
import { NetworkBadge } from "@/components/NetworkBadge";
import { SearchBar } from "@/components/SearchBar";
import { LocaleSwitcher } from "@/components/LocaleSwitcher";
import '@/lib/i18n';
import { useTranslation } from 'react-i18next';

export function Header() {
  const { t } = useTranslation();

  return (
    <header className="border-b border-white/5 bg-neutral-950/60 backdrop-blur-xl sticky top-0 z-50">
      <nav className="container mx-auto px-6 py-4 flex justify-between items-center gap-4">
        <Link href="/" className="flex items-center gap-2 shrink-0 lg:mr-4">
          <div className="w-8 h-8 bg-indigo-500 rounded-lg flex items-center justify-center font-bold italic">
            Q
          </div>
          <span className="text-xl font-bold tracking-tight">QuickEx</span>
        </Link>
        <NetworkBadge />
        <div className="hidden md:flex gap-8 text-sm text-neutral-400 font-medium">
          <Link href="/dashboard" className="hover:text-white transition">
            {t('dashboard')}
          </Link>
          <Link href="/generator" className="hover:text-white transition">
            {t('linkGenerator')}
          </Link>
          <Link href="/settings" className="hover:text-white transition">
            {t('profileSettings')}
          </Link>
        </div>

        <div className="flex items-center gap-4">
          <LocaleSwitcher />
          <div className="md:hidden text-neutral-400">☰</div>
        </div>
      </nav>
    </header>
  );
}
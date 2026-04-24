"use client";

import Link from "next/link";
import { LocaleSwitcher } from "@/components/LocaleSwitcher";
import { NotificationBell } from "@/components/NotificationBell";
import "@/lib/i18n";
import { useTranslation } from "react-i18next";

export function Header() {
  const { t } = useTranslation();

  return (
    <header className="sticky top-0 z-50 border-b border-white/5 bg-neutral-950/80 backdrop-blur-xl">
      <nav
        aria-label="Primary navigation"
        className="container mx-auto flex items-center justify-between gap-4 px-6 py-4"
      >
        <Link href="/" className="flex shrink-0 items-center gap-2 lg:mr-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500 font-bold italic">
            Q
          </div>
          <span className="text-xl font-bold tracking-tight">QuickEx</span>
        </Link>

        <div className="hidden gap-8 text-sm font-medium text-neutral-300 md:flex">
          <Link href="/dashboard" className="transition hover:text-white">
            {t("dashboard")}
          </Link>
          <Link href="/generator" className="transition hover:text-white">
            {t("linkGenerator")}
          </Link>
          <Link
            href="/notifications"
            className="transition hover:text-white"
          >
            Notifications
          </Link>
          <Link href="/settings" className="transition hover:text-white">
            {t("profileSettings")}
          </Link>
        </div>

        <div className="flex items-center gap-4">
          <NotificationBell />
          <LocaleSwitcher />
          <div className="text-neutral-300 md:hidden">Menu</div>
        </div>
      </nav>
    </header>
  );
}

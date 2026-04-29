"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LocaleSwitcher } from "@/components/LocaleSwitcher";
import { NotificationBell } from "@/components/NotificationBell";
import "@/lib/i18n";
import { useTranslation } from "react-i18next";

const NAV_LINK_CLASS =
  "rounded-md px-1 py-1 text-neutral-200 transition hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-neutral-950";

export function Header() {
  const { t } = useTranslation();
  const pathname = usePathname();

  const isActive = (href: string) =>
    pathname === href || pathname?.startsWith(`${href}/`);

  return (
    <header className="sticky top-0 z-50 border-b border-white/5 bg-neutral-950/80 backdrop-blur-xl">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-indigo-500 focus:px-3 focus:py-2 focus:text-sm focus:font-semibold focus:text-white"
      >
        Skip to main content
      </a>
      <nav
        aria-label="Primary navigation"
        className="container mx-auto flex items-center justify-between gap-4 px-6 py-4"
      >
        <Link
          href="/"
          aria-label="QuickEx home"
          className={`flex shrink-0 items-center gap-2 lg:mr-4 ${NAV_LINK_CLASS}`}
        >
          <div
            aria-hidden="true"
            className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500 font-bold italic"
          >
            Q
          </div>
          <span className="text-xl font-bold tracking-tight text-white">
            QuickEx
          </span>
        </Link>

        <div className="hidden gap-8 text-sm font-medium md:flex">
          <Link
            href="/dashboard"
            aria-current={isActive("/dashboard") ? "page" : undefined}
            className={`${NAV_LINK_CLASS} ${
              isActive("/dashboard") ? "text-white" : ""
            }`}
          >
            {t("dashboard")}
          </Link>
          <Link
            href="/generator"
            aria-current={isActive("/generator") ? "page" : undefined}
            className={`${NAV_LINK_CLASS} ${
              isActive("/generator") ? "text-white" : ""
            }`}
          >
            {t("linkGenerator")}
          </Link>
          <Link
            href="/notifications"
            aria-current={isActive("/notifications") ? "page" : undefined}
            className={`${NAV_LINK_CLASS} ${
              isActive("/notifications") ? "text-white" : ""
            }`}
          >
            Notifications
          </Link>
          <Link
            href="/settings"
            aria-current={isActive("/settings") ? "page" : undefined}
            className={`${NAV_LINK_CLASS} ${
              isActive("/settings") ? "text-white" : ""
            }`}
          >
            {t("profileSettings")}
          </Link>
        </div>

        <div className="flex items-center gap-4">
          <NotificationBell />
          <LocaleSwitcher />
        </div>
      </nav>
    </header>
  );
}

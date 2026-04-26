"use client";

import { useState } from "react";
import Link from "next/link";
import { NetworkBadge } from "@/components/NetworkBadge";
import { LocaleSwitcher } from "@/components/LocaleSwitcher";
import '@/lib/i18n';
import { useTranslation } from "react-i18next";

export default function Settings() {
  const { t } = useTranslation();
  const [form, setForm] = useState({
    username: "john_doe",
    primaryColor: "#6366f1",
    avatarUrl: "",
    bio: "",
    twitterHandle: "",
    discordHandle: "",
    githubHandle: "",
  });

  const [showPreview, setShowPreview] = useState(false);

  const handleSave = () => {
    console.log("Saving profile:", form);
    // TODO: Call API to save profile
  };

  return (
    <div className="relative min-h-screen text-white selection:bg-indigo-500/30">
      <NetworkBadge />

      {/* Background glows */}
      <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px] rounded-full" />
      <div className="fixed bottom-[-20%] right-[-30%] w-[50%] h-[50%] bg-purple-500/5 blur-[100px] rounded-full" />

      {/* MOBILE HEADER */}
      <div className="md:hidden relative z-10 p-4 border-b border-white/5 bg-black/20 backdrop-blur-3xl">
        <div className="flex items-center justify-between">
          <Link
            href="/dashboard"
            className="text-neutral-400 hover:text-white transition"
          >
            ← Back
          </Link>
          <h1 className="text-lg font-black">{t('settingsTitle')}</h1>
          <div className="w-16" /> {/* Spacer for centering */}
        </div>
      </div>

      {/* DESKTOP SIDEBAR */}
      <aside className="hidden md:flex w-72 h-screen fixed left-0 top-0 border-r border-white/5 bg-black/20 backdrop-blur-3xl flex-col z-20">
        <nav className="flex-1 px-4 py-30 space-y-2">
          <Link
            href="/dashboard"
            className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 rounded-2xl font-semibold transition"
          >
            <span>📊</span> Dashboard
          </Link>
          <Link
            href="/generator"
            className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 rounded-2xl font-semibold transition"
          >
            <span>⚡</span> Link Generator
          </Link>
          <Link
            href="/settings"
            className="flex items-center gap-3 px-4 py-3 bg-white/5 border border-white/5 rounded-2xl font-bold"
          >
            <span className="text-indigo-400">⚙️</span> Profile Settings
          </Link>
          <Link
            href="/settings/teams"
            className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 rounded-2xl font-semibold transition"
          >
            <span>👥</span> Team Management
          </Link>
        </nav>
      </aside>

      {/* MAIN CONTENT */}
      <main className="relative z-10 p-4 sm:p-6 md:p-12 md:ml-72 pb-24 md:pb-12">
        {/* Header - Hidden on mobile, shown on desktop */}
        <header className="hidden md:block mb-10">
          <h1 className="text-3xl sm:text-4xl font-black tracking-tight mb-2">
            {t('profileCustomization')}
          </h1>
          <p className="text-neutral-500 font-medium text-sm sm:text-base">
            {t('profileCustomizationDescription', { username: form.username })}
          </p>
        </header>

        {/* Mobile subheader */}
        <div className="md:hidden mb-6">
          <p className="text-neutral-400 text-sm">
            {t('profileCustomizationDescription', { username: form.username })}
          </p>
        </div>

        <nav className="flex gap-3 mb-8">
          <Link
            href="/settings"
            className="px-4 py-2 rounded-xl border border-white/10 bg-white/10 text-sm font-semibold hover:bg-white/20"
          >
            {t('generalTab')}
          </Link>
          <Link
            href="/settings/teams"
            className="px-4 py-2 rounded-xl border border-white/10 text-sm font-semibold hover:bg-white/5"
          >
            Team
          </Link>
          <Link
            href="/settings/developer"
            className="px-4 py-2 rounded-xl border border-white/10 text-sm font-semibold hover:bg-white/5"
          >
            {t('developerTab')}
          </Link>
        </nav>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6 lg:gap-8">
          {/* Settings Form */}
          <div className="space-y-4 sm:space-y-6">
            {/* Theme Settings Card */}
            <div className="rounded-2xl sm:rounded-3xl bg-black/40 border border-white/5 p-5 sm:p-6 md:p-8">
              <h2 className="text-lg sm:text-xl font-bold mb-4 sm:mb-6">
                {t('themeSettings')}
              </h2>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs sm:text-sm font-bold text-neutral-400 mb-2">
                    {t('primaryColor')}
                  </label>
                  <div className="flex gap-2 sm:gap-3">
                    <input
                      type="color"
                      value={form.primaryColor}
                      onChange={(e) =>
                        setForm({ ...form, primaryColor: e.target.value })
                      }
                      className="w-14 sm:w-16 h-11 sm:h-12 rounded-xl border border-white/10 bg-transparent cursor-pointer"
                    />
                    <input
                      type="text"
                      value={form.primaryColor}
                      onChange={(e) =>
                        setForm({ ...form, primaryColor: e.target.value })
                      }
                      className="flex-1 px-3 sm:px-4 py-2.5 sm:py-3 rounded-xl bg-white/5 border border-white/10 text-white font-mono text-sm sm:text-base"
                      placeholder="#6366f1"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs sm:text-sm font-bold text-neutral-400 mb-2">
                    {t('avatarUrl')}
                  </label>
                  <input
                    type="url"
                    value={form.avatarUrl}
                    onChange={(e) =>
                      setForm({ ...form, avatarUrl: e.target.value })
                    }
                    className="w-full px-3 sm:px-4 py-2.5 sm:py-3 rounded-xl bg-white/5 border border-white/10 text-white text-sm sm:text-base"
                    placeholder="https://example.com/avatar.jpg"
                  />
                </div>

                <div>
                  <label className="block text-xs sm:text-sm font-bold text-neutral-400 mb-2">
                    {t('bioLabel')}
                  </label>
                  <textarea
                    value={form.bio}
                    onChange={(e) => setForm({ ...form, bio: e.target.value })}
                    maxLength={160}
                    rows={3}
                    className="w-full px-3 sm:px-4 py-2.5 sm:py-3 rounded-xl bg-white/5 border border-white/10 text-white resize-none text-sm sm:text-base"
                    placeholder="Building the future of payments on Stellar"
                  />
                  <p className="text-xs text-neutral-600 mt-1">
                    {form.bio.length}/160 characters
                  </p>
                </div>
              </div>
            </div>

            <div className="rounded-2xl sm:rounded-3xl bg-black/40 border border-white/5 p-5 sm:p-6 md:p-8">
              <h2 className="text-lg sm:text-xl font-bold mb-4 sm:mb-6">
                {t('languageLabel')}
              </h2>
              <p className="text-sm text-neutral-400 mb-4">
                {t('changeLanguage')}
              </p>
              <LocaleSwitcher />
            </div>

            {/* Social Links Card */}
            <div className="rounded-2xl sm:rounded-3xl bg-black/40 border border-white/5 p-5 sm:p-6 md:p-8">
              <h2 className="text-lg sm:text-xl font-bold mb-4 sm:mb-6">
                Social Links
              </h2>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs sm:text-sm font-bold text-neutral-400 mb-2">
                    {t('twitterHandleLabel')}
                  </label>
                  <div className="flex items-center gap-2">
                    <span className="text-neutral-500 text-sm sm:text-base">
                      @
                    </span>
                    <input
                      type="text"
                      value={form.twitterHandle}
                      onChange={(e) =>
                        setForm({ ...form, twitterHandle: e.target.value })
                      }
                      className="flex-1 px-3 sm:px-4 py-2.5 sm:py-3 rounded-xl bg-white/5 border border-white/10 text-white text-sm sm:text-base"
                      placeholder="stellarorg"
                      maxLength={15}
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs sm:text-sm font-bold text-neutral-400 mb-2">
                    {t('discordUsernameLabel')}
                  </label>
                  <input
                    type="text"
                    value={form.discordHandle}
                    onChange={(e) =>
                      setForm({ ...form, discordHandle: e.target.value })
                    }
                    className="w-full px-3 sm:px-4 py-2.5 sm:py-3 rounded-xl bg-white/5 border border-white/10 text-white text-sm sm:text-base"
                    placeholder="user#1234"
                    maxLength={32}
                  />
                </div>

                <div>
                  <label className="block text-xs sm:text-sm font-bold text-neutral-400 mb-2">
                    {t('githubHandleLabel')}
                  </label>
                  <input
                    type="text"
                    value={form.githubHandle}
                    onChange={(e) =>
                      setForm({ ...form, githubHandle: e.target.value })
                    }
                    className="w-full px-3 sm:px-4 py-2.5 sm:py-3 rounded-xl bg-white/5 border border-white/10 text-white text-sm sm:text-base"
                    placeholder="stellar"
                    maxLength={39}
                  />
                </div>
              </div>
            </div>

            {/* Action Buttons - Desktop */}
            <div className="hidden sm:flex gap-3 sm:gap-4">
              <button
                onClick={handleSave}
                className="flex-1 px-4 sm:px-6 py-3 sm:py-4 bg-indigo-500 text-white font-bold rounded-xl hover:scale-105 active:scale-95 transition text-sm sm:text-base"
              >
                {t('saveChanges')}
              </button>
              <button
                onClick={() => setShowPreview(!showPreview)}
                className="px-4 sm:px-6 py-3 sm:py-4 bg-white/5 border border-white/10 text-white font-bold rounded-xl hover:bg-white/10 transition text-sm sm:text-base whitespace-nowrap"
              >
                {showPreview ? t('hide') : t('show')} {t('preview')}
              </button>
            </div>
          </div>

          {/* Live Preview - Desktop */}
          {showPreview && (
            <div className="hidden lg:block lg:sticky lg:top-12 h-fit">
              <div className="rounded-3xl bg-black/40 border border-white/5 p-8">
                <h2 className="text-xl font-bold mb-6">{t('livePreview')}</h2>
                <div className="rounded-2xl border border-white/10 overflow-hidden bg-neutral-950">
                  <ProfilePreview {...form} />
                </div>
              </div>
            </div>
          )}

          {/* Live Preview - Mobile/Tablet (when toggled) */}
          {showPreview && (
            <div className="lg:hidden rounded-2xl sm:rounded-3xl bg-black/40 border border-white/5 p-5 sm:p-6 md:p-8">
              <h2 className="text-lg sm:text-xl font-bold mb-4 sm:mb-6">
                {t('livePreview')}
              </h2>
              <div className="rounded-2xl border border-white/10 overflow-hidden bg-neutral-950">
                <ProfilePreview {...form} />
              </div>
            </div>
          )}
        </div>
      </main>

      {/* MOBILE BOTTOM BAR */}
      <div className="sm:hidden fixed bottom-0 left-0 right-0 z-30 p-4 bg-black/80 backdrop-blur-3xl border-t border-white/5">
        <div className="flex gap-3">
          <button
            onClick={handleSave}
            className="flex-1 px-4 py-3 bg-indigo-500 text-white font-bold rounded-xl active:scale-95 transition"
          >
            {t('saveChanges')}
          </button>
          <button
            onClick={() => setShowPreview(!showPreview)}
            className="px-4 py-3 bg-white/5 border border-white/10 text-white font-bold rounded-xl active:scale-95 transition"
          >
            {showPreview ? t('hide') : t('show')} {t('preview')}
          </button>
        </div>
      </div>
    </div>
  );
}

function ProfilePreview({
  username,
  primaryColor,
  avatarUrl,
  bio,
  twitterHandle,
  discordHandle,
  githubHandle,
}: {
  username: string;
  primaryColor: string;
  avatarUrl: string;
  bio: string;
  twitterHandle: string;
  discordHandle: string;
  githubHandle: string;
}) {
  return (
    <div className="p-6 sm:p-8 text-center">
      {/* Avatar */}
      <div className="flex justify-center mb-4 sm:mb-6">
        {avatarUrl ? (
          <img
            src={avatarUrl}
            alt={username}
            className="w-20 h-20 sm:w-24 sm:h-24 rounded-full border-4 object-cover"
            style={{ borderColor: primaryColor }}
          />
        ) : (
          <div
            className="w-20 h-20 sm:w-24 sm:h-24 rounded-full border-4 flex items-center justify-center text-2xl sm:text-3xl font-black"
            style={{ borderColor: primaryColor, color: primaryColor }}
          >
            {username[0]?.toUpperCase()}
          </div>
        )}
      </div>

      {/* Username */}
      <h1 className="text-xl sm:text-2xl font-black mb-2">@{username}</h1>

      {/* Bio */}
      {bio && (
        <p className="text-neutral-400 text-xs sm:text-sm mb-4 sm:mb-6 px-2">
          {bio}
        </p>
      )}

      {/* Social Links */}
      {(twitterHandle || discordHandle || githubHandle) && (
        <div className="flex justify-center gap-2 sm:gap-3 mb-4 sm:mb-6">
          {twitterHandle && (
            <a
              href={`https://twitter.com/${twitterHandle}`}
              target="_blank"
              rel="noopener noreferrer"
              className="w-9 h-9 sm:w-10 sm:h-10 rounded-full bg-white/5 hover:bg-white/10 flex items-center justify-center transition text-sm sm:text-base"
              style={{ color: primaryColor }}
            >
              𝕏
            </a>
          )}
          {discordHandle && (
            <div
              className="w-9 h-9 sm:w-10 sm:h-10 rounded-full bg-white/5 flex items-center justify-center text-sm sm:text-base"
              style={{ color: primaryColor }}
            >
              💬
            </div>
          )}
          {githubHandle && (
            <a
              href={`https://github.com/${githubHandle}`}
              target="_blank"
              rel="noopener noreferrer"
              className="w-9 h-9 sm:w-10 sm:h-10 rounded-full bg-white/5 hover:bg-white/10 flex items-center justify-center transition text-sm sm:text-base"
              style={{ color: primaryColor }}
            >
              🐙
            </a>
          )}
        </div>
      )}

      {/* Payment Button */}
      <button
        className="w-full py-3 sm:py-4 rounded-xl font-bold text-white transition hover:opacity-90 text-sm sm:text-base"
        style={{ backgroundColor: primaryColor }}
      >
        Send Payment
      </button>
    </div>
  );
}

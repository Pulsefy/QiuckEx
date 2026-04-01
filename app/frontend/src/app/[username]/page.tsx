"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { NetworkBadge } from "@/components/NetworkBadge";
import { QRPreview } from "@/components/QRPreview";

type Profile = {
  username: string;
  publicKey: string;
  primaryColor?: string;
  avatarUrl?: string;
  bio?: string;
  twitterHandle?: string;
  discordHandle?: string;
  githubHandle?: string;
};

export default function PublicProfile() {
  const params = useParams();
  const username = params.username as string;

  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [paymentForm, setPaymentForm] = useState({
    amount: "",
    asset: "USDC",
    memo: "",
  });

  useEffect(() => {
    // TODO: Fetch profile from API
    // Mock data for now
    setTimeout(() => {
      setProfile({
        username,
        publicKey: "GABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        primaryColor: "#6366f1",
        avatarUrl: "",
        bio: "Building the future of payments on Stellar",
        twitterHandle: "stellarorg",
        discordHandle: "",
        githubHandle: "stellar",
      });
      setLoading(false);
    }, 500);
  }, [username]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-white">
        <p>Loading profile...</p>
      </div>
    );
  }

  if (error || !profile) {
    return (
      <div className="min-h-screen flex items-center justify-center text-white">
        <div className="text-center">
          <h1 className="text-4xl font-black mb-4">404</h1>
          <p className="text-neutral-400">Username not found</p>
        </div>
      </div>
    );
  }

  const primaryColor = profile.primaryColor || "#6366f1";

  return (
    <div className="relative min-h-screen text-white">
      <NetworkBadge />

      {/* Background glows with theme color */}
      <div
        className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] blur-[120px] rounded-full opacity-10"
        style={{ backgroundColor: primaryColor }}
      />
      <div
        className="fixed bottom-[-20%] right-[-30%] w-[50%] h-[50%] blur-[100px] rounded-full opacity-5"
        style={{ backgroundColor: primaryColor }}
      />

      {/* MAIN CONTENT */}
      <main className="relative z-10 max-w-2xl mx-auto p-4 sm:p-6 md:p-12">
        {/* Profile Header */}
        <div className="text-center mb-12">
          {/* Avatar */}
          <div className="flex justify-center mb-6">
            {profile.avatarUrl ? (
              <img
                src={profile.avatarUrl}
                alt={profile.username}
                className="w-32 h-32 rounded-full border-4 object-cover"
                style={{ borderColor: primaryColor }}
              />
            ) : (
              <div
                className="w-32 h-32 rounded-full border-4 flex items-center justify-center text-5xl font-black"
                style={{ borderColor: primaryColor, color: primaryColor }}
              >
                {profile.username[0]?.toUpperCase()}
              </div>
            )}
          </div>

          {/* Username */}
          <h1 className="text-4xl font-black mb-3">@{profile.username}</h1>

          {/* Bio */}
          {profile.bio && (
            <p className="text-neutral-400 text-lg mb-6 max-w-md mx-auto">
              {profile.bio}
            </p>
          )}

          {/* Social Links */}
          {(profile.twitterHandle || profile.discordHandle || profile.githubHandle) && (
            <div className="flex justify-center gap-4 mb-8">
              {profile.twitterHandle && (
                <a
                  href={`https://twitter.com/${profile.twitterHandle}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-12 h-12 rounded-full bg-white/5 hover:bg-white/10 flex items-center justify-center transition text-xl"
                  style={{ color: primaryColor }}
                >
                  𝕏
                </a>
              )}
              {profile.discordHandle && (
                <div
                  className="w-12 h-12 rounded-full bg-white/5 flex items-center justify-center text-xl"
                  style={{ color: primaryColor }}
                >
                  💬
                </div>
              )}
              {profile.githubHandle && (
                <a
                  href={`https://github.com/${profile.githubHandle}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-12 h-12 rounded-full bg-white/5 hover:bg-white/10 flex items-center justify-center transition text-xl"
                  style={{ color: primaryColor }}
                >
                  🐙
                </a>
              )}
            </div>
          )}
        </div>

        {/* Payment Form */}
        <div className="rounded-3xl bg-black/40 border border-white/5 backdrop-blur-2xl p-8 mb-8">
          <h2 className="text-2xl font-black mb-6">Send Payment</h2>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-bold text-neutral-400 mb-2">
                Amount
              </label>
              <input
                type="number"
                value={paymentForm.amount}
                onChange={(e) => setPaymentForm({ ...paymentForm, amount: e.target.value })}
                className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white text-lg"
                placeholder="0.00"
                step="0.01"
              />
            </div>

            <div>
              <label className="block text-sm font-bold text-neutral-400 mb-2">
                Asset
              </label>
              <select
                value={paymentForm.asset}
                onChange={(e) => setPaymentForm({ ...paymentForm, asset: e.target.value })}
                className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white"
              >
                <option value="USDC">USDC</option>
                <option value="XLM">XLM</option>
                <option value="AQUA">AQUA</option>
                <option value="yXLM">yXLM</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-bold text-neutral-400 mb-2">
                Memo (optional)
              </label>
              <input
                type="text"
                value={paymentForm.memo}
                onChange={(e) => setPaymentForm({ ...paymentForm, memo: e.target.value })}
                className="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-white"
                placeholder="Payment for..."
                maxLength={28}
              />
            </div>

            <button
              className="w-full py-4 rounded-xl font-bold text-white transition hover:opacity-90 mt-6"
              style={{ backgroundColor: primaryColor }}
            >
              Generate Payment Link
            </button>
          </div>
        </div>

        {/* QR Code Preview */}
        {paymentForm.amount && (
          <div className="rounded-3xl bg-black/40 border border-white/5 backdrop-blur-2xl p-8">
            <h3 className="text-xl font-bold mb-4">Payment QR Code</h3>
            <QRPreview
              value={JSON.stringify({
                destination: profile.publicKey,
                amount: paymentForm.amount,
                asset: paymentForm.asset,
                memo: paymentForm.memo,
              })}
            />
          </div>
        )}

        {/* Footer */}
        <div className="text-center mt-12 text-neutral-600 text-sm">
          <p>Powered by QuickEx • Stellar Network</p>
        </div>
      </main>
    </div>
  );
}

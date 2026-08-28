/**
 * GET /api/og/profile
 * Dynamic Open Graph image for user profile pages.
 *
 * Query params:
 *   username  – QuickEx username (required)
 *
 * Edge-cached for 1 hour (Cache-Control: public, max-age=3600, s-maxage=3600).
 * Falls back to default OG image when username is missing.
 *
 * Uses Next.js ImageResponse (@vercel/og / Satori) — no external deps.
 */

import { ImageResponse } from "next/og";
import { NextRequest } from "next/server";

export const runtime = "edge";

const WIDTH = 1200;
const HEIGHT = 630;
const CACHE_TTL = 3600; // 1 hour

// Brand palette
const BG = "#0a0a0a";
const ACCENT = "#6366f1";
const TEXT_PRIMARY = "#ffffff";
const TEXT_SECONDARY = "#a3a3a3";
const CARD_BG = "rgba(255,255,255,0.04)";
const CARD_BORDER = "rgba(255,255,255,0.08)";

// ---------------------------------------------------------------------------
// Sanitisation (edge-safe)
// ---------------------------------------------------------------------------

function sanitizeUsername(v: string | null): string {
  if (!v) return "";
  return v.replace(/[^\w.\-]/g, "").slice(0, 32).trim();
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;
  const username = sanitizeUsername(searchParams.get("username"));

  if (!username) {
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/api/og",
        "Cache-Control": "no-store",
      },
    });
  }

  const initial = username[0].toUpperCase();

  const image = new ImageResponse(
    (
      <div
        style={{
          width: WIDTH,
          height: HEIGHT,
          background: BG,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          fontFamily: "sans-serif",
          position: "relative",
        }}
      >
        {/* Top-left glow */}
        <div
          style={{
            position: "absolute",
            top: -80,
            left: -80,
            width: 500,
            height: 500,
            borderRadius: "50%",
            background: ACCENT,
            opacity: 0.06,
            filter: "blur(100px)",
          }}
        />
        {/* Bottom-right glow */}
        <div
          style={{
            position: "absolute",
            bottom: -100,
            right: -100,
            width: 500,
            height: 500,
            borderRadius: "50%",
            background: ACCENT,
            opacity: 0.07,
            filter: "blur(100px)",
          }}
        />

        {/* Avatar */}
        <div
          style={{
            width: 120,
            height: 120,
            borderRadius: "50%",
            background: `${ACCENT}33`,
            border: `3px solid ${ACCENT}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 56,
            fontWeight: 900,
            color: ACCENT,
            marginBottom: 32,
          }}
        >
          {initial}
        </div>

        {/* Username */}
        <div
          style={{
            fontSize: 60,
            fontWeight: 900,
            color: TEXT_PRIMARY,
            marginBottom: 16,
          }}
        >
          @{username}
        </div>

        {/* Sub-headline */}
        <div
          style={{
            fontSize: 28,
            color: TEXT_SECONDARY,
            marginBottom: 48,
          }}
        >
          Send a payment on Stellar
        </div>

        {/* Brand pill */}
        <div
          style={{
            background: CARD_BG,
            border: `1px solid ${CARD_BORDER}`,
            borderRadius: 100,
            padding: "10px 28px",
            fontSize: 20,
            color: TEXT_SECONDARY,
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <span style={{ color: ACCENT }}>⚡</span> QuickEx · Stellar Network
        </div>
      </div>
    ),
    { width: WIDTH, height: HEIGHT },
  );

  const headers = new Headers(image.headers);
  headers.set(
    "Cache-Control",
    `public, max-age=${CACHE_TTL}, s-maxage=${CACHE_TTL}, stale-while-revalidate=60`,
  );

  return new Response(image.body, {
    status: image.status,
    headers,
  });
}

/**
 * GET /api/og/payment-link
 * Dynamic Open Graph image for payment links.
 *
 * Query params:
 *   username  – QuickEx username (required)
 *   amount    – numeric amount
 *   asset     – asset code (default: XLM)
 *   state     – ACTIVE | EXPIRED | PAID | REFUNDED | DRAFT | UNKNOWN
 *
 * Edge-cached for 1 hour (Cache-Control: public, max-age=3600, s-maxage=3600).
 * Falls back to default OG image on invalid params.
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

type PaymentState =
  | "ACTIVE"
  | "EXPIRED"
  | "PAID"
  | "REFUNDED"
  | "DRAFT"
  | "UNKNOWN";

// ---------------------------------------------------------------------------
// Sanitisation helpers (edge-safe)
// ---------------------------------------------------------------------------

function sanitizeText(v: string | null, maxLen = 32): string {
  if (!v) return "";
  return v.replace(/[^\w\s\-_.#@]/g, "").slice(0, maxLen).trim();
}

function sanitizeAmount(v: string | null): string {
  if (!v) return "";
  const n = parseFloat(v);
  if (isNaN(n) || n < 0) return "";
  return n.toLocaleString("en-US", { maximumFractionDigits: 7 });
}

function sanitizeAsset(v: string | null): string {
  if (!v) return "XLM";
  return v.replace(/[^A-Z0-9]/gi, "").slice(0, 12).toUpperCase() || "XLM";
}

function isValidState(v: string | null): v is PaymentState {
  return [
    "ACTIVE",
    "EXPIRED",
    "PAID",
    "REFUNDED",
    "DRAFT",
    "UNKNOWN",
  ].includes(v ?? "");
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

function stateBadgeColor(state: PaymentState): string {
  switch (state) {
    case "ACTIVE":
    case "DRAFT":
      return "#22c55e";
    case "PAID":
      return "#6366f1";
    case "EXPIRED":
      return "#f59e0b";
    case "REFUNDED":
      return "#64748b";
    default:
      return "#6b7280";
  }
}

function stateLabel(state: PaymentState): string {
  const labels: Record<PaymentState, string> = {
    ACTIVE: "Active",
    DRAFT: "Pending",
    PAID: "Paid",
    EXPIRED: "Expired",
    REFUNDED: "Refunded",
    UNKNOWN: "Unavailable",
  };
  return labels[state] ?? "Unavailable";
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;

  const username = sanitizeText(searchParams.get("username")) || undefined;
  const amount = sanitizeAmount(searchParams.get("amount")) || undefined;
  const asset = sanitizeAsset(searchParams.get("asset"));
  const rawState = searchParams.get("state");
  const state: PaymentState = isValidState(rawState) ? rawState : "UNKNOWN";

  // Fallback: no username → return default OG
  if (!username) {
    return new Response(null, {
      status: 302,
      headers: {
        Location: "/api/og",
        "Cache-Control": "no-store",
      },
    });
  }

  const badgeColor = stateBadgeColor(state);
  const label = stateLabel(state);
  const isUnavailable = state === "EXPIRED" || state === "UNKNOWN";

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
          padding: "0 80px",
        }}
      >
        {/* Background glow */}
        <div
          style={{
            position: "absolute",
            top: -80,
            right: -80,
            width: 500,
            height: 500,
            borderRadius: "50%",
            background: isUnavailable ? "#f59e0b" : ACCENT,
            opacity: 0.06,
            filter: "blur(100px)",
          }}
        />
        {/* Bottom-left glow */}
        <div
          style={{
            position: "absolute",
            bottom: -60,
            left: -60,
            width: 400,
            height: 400,
            borderRadius: "50%",
            background: "#22c55e",
            opacity: 0.04,
            filter: "blur(80px)",
          }}
        />

        {/* Card */}
        <div
          style={{
            background: CARD_BG,
            border: `1px solid ${CARD_BORDER}`,
            borderRadius: 32,
            padding: "56px 72px",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            width: "100%",
            maxWidth: 920,
          }}
        >
          {/* Brand */}
          <div
            style={{
              fontSize: 22,
              color: TEXT_SECONDARY,
              marginBottom: 32,
              display: "flex",
              alignItems: "center",
              gap: 10,
            }}
          >
            <span style={{ color: ACCENT }}>⚡</span> QuickEx
          </div>

          {/* State badge */}
          <div
            style={{
              background: `${badgeColor}22`,
              border: `1px solid ${badgeColor}55`,
              borderRadius: 100,
              padding: "6px 20px",
              fontSize: 18,
              color: badgeColor,
              fontWeight: 700,
              marginBottom: 28,
            }}
          >
            {label}
          </div>

          {/* Main content */}
          {isUnavailable ? (
            <div
              style={{
                fontSize: 40,
                fontWeight: 900,
                color: TEXT_PRIMARY,
                textAlign: "center",
              }}
            >
              This payment link is {label.toLowerCase()}
            </div>
          ) : (
            <>
              {amount && (
                <div
                  style={{
                    fontSize: 72,
                    fontWeight: 900,
                    color: TEXT_PRIMARY,
                    letterSpacing: "-2px",
                    marginBottom: 8,
                  }}
                >
                  {amount}{" "}
                  <span style={{ color: ACCENT }}>{asset}</span>
                </div>
              )}
              <div
                style={{
                  fontSize: 32,
                  color: TEXT_SECONDARY,
                  marginTop: 8,
                }}
              >
                to{" "}
                <span style={{ color: TEXT_PRIMARY, fontWeight: 700 }}>
                  @{username}
                </span>
              </div>
            </>
          )}

          {/* Footer */}
          <div
            style={{ marginTop: 40, fontSize: 18, color: TEXT_SECONDARY }}
          >
            Powered by Stellar Network
          </div>
        </div>
      </div>
    ),
    { width: WIDTH, height: HEIGHT },
  );

  // Set 1-hour edge cache headers
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

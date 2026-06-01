/**
 * Dynamic OG image generation endpoint.
 *
 * GET /api/og                          → default site image
 * GET /api/og?type=payment&username=X&amount=100&asset=XLM&state=ACTIVE
 * GET /api/og?type=profile&username=X
 *
 * Uses Next.js ImageResponse (built on @vercel/og / Satori) to render
 * a 1200×630 PNG at request time.
 *
 * Privacy: only username, amount, asset, and state are accepted.
 * No keys, hashes, or internal data are rendered.
 */

import { ImageResponse } from "next/og";
import { NextRequest } from "next/server";

export const runtime = "edge";

const WIDTH = 1200;
const HEIGHT = 630;

// Brand colours
const BG = "#0a0a0a";
const ACCENT = "#6366f1"; // indigo-500
const TEXT_PRIMARY = "#ffffff";
const TEXT_SECONDARY = "#a3a3a3"; // neutral-400
const CARD_BG = "rgba(255,255,255,0.04)";
const CARD_BORDER = "rgba(255,255,255,0.08)";

type OgType = "payment" | "profile" | "default";
type PaymentState = "ACTIVE" | "EXPIRED" | "PAID" | "REFUNDED" | "DRAFT" | "UNKNOWN";

interface OgParams {
  type: OgType;
  username?: string;
  amount?: string;
  asset?: string;
  state?: PaymentState;
}

// ---------------------------------------------------------------------------
// Sanitisation (edge-safe, no external deps)
// ---------------------------------------------------------------------------

function sanitizeText(v: string | null, maxLen = 64): string {
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
  return ["ACTIVE", "EXPIRED", "PAID", "REFUNDED", "DRAFT", "UNKNOWN"].includes(v ?? "");
}

// ---------------------------------------------------------------------------
// State badge helpers
// ---------------------------------------------------------------------------

function stateBadgeColor(state: PaymentState): string {
  switch (state) {
    case "ACTIVE":
    case "DRAFT":
      return "#22c55e"; // green-500
    case "PAID":
      return "#6366f1"; // indigo-500
    case "EXPIRED":
      return "#f59e0b"; // amber-500
    case "REFUNDED":
      return "#64748b"; // slate-500
    default:
      return "#6b7280"; // gray-500
  }
}

function stateLabel(state: PaymentState): string {
  switch (state) {
    case "ACTIVE":
      return "Active";
    case "DRAFT":
      return "Pending";
    case "PAID":
      return "Paid";
    case "EXPIRED":
      return "Expired";
    case "REFUNDED":
      return "Refunded";
    default:
      return "Unavailable";
  }
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;

  const rawType = searchParams.get("type") ?? "default";
  const type: OgType = ["payment", "profile"].includes(rawType)
    ? (rawType as OgType)
    : "default";

  const params: OgParams = {
    type,
    username: sanitizeText(searchParams.get("username"), 32) || undefined,
    amount: sanitizeAmount(searchParams.get("amount")) || undefined,
    asset: sanitizeAsset(searchParams.get("asset")),
    state: isValidState(searchParams.get("state"))
      ? (searchParams.get("state") as PaymentState)
      : "UNKNOWN",
  };

  return new ImageResponse(renderImage(params), {
    width: WIDTH,
    height: HEIGHT,
  });
}

// ---------------------------------------------------------------------------
// Image renderers
// ---------------------------------------------------------------------------

function renderImage(params: OgParams) {
  switch (params.type) {
    case "payment":
      return renderPaymentImage(params);
    case "profile":
      return renderProfileImage(params);
    default:
      return renderDefaultImage();
  }
}

function renderDefaultImage() {
  return (
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
      {/* Glow */}
      <div
        style={{
          position: "absolute",
          top: -100,
          left: -100,
          width: 600,
          height: 600,
          borderRadius: "50%",
          background: ACCENT,
          opacity: 0.08,
          filter: "blur(80px)",
        }}
      />
      {/* Logo mark */}
      <div
        style={{
          width: 80,
          height: 80,
          borderRadius: 20,
          background: ACCENT,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: 40,
          marginBottom: 32,
        }}
      >
        ⚡
      </div>
      <div style={{ fontSize: 64, fontWeight: 900, color: TEXT_PRIMARY, marginBottom: 16 }}>
        QuickEx
      </div>
      <div style={{ fontSize: 28, color: TEXT_SECONDARY, textAlign: "center", maxWidth: 700 }}>
        Privacy-focused payments on Stellar
      </div>
    </div>
  );
}

function renderPaymentImage(params: OgParams) {
  const { username, amount, asset = "XLM", state = "UNKNOWN" } = params;
  const badgeColor = stateBadgeColor(state);
  const label = stateLabel(state);
  const isUnavailable = state === "EXPIRED" || state === "UNKNOWN";

  return (
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
          maxWidth: 900,
          gap: 0,
        }}
      >
        {/* Site name */}
        <div style={{ fontSize: 22, color: TEXT_SECONDARY, marginBottom: 32, display: "flex", alignItems: "center", gap: 10 }}>
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
          <div style={{ fontSize: 40, fontWeight: 900, color: TEXT_PRIMARY, textAlign: "center" }}>
            This payment link is {label.toLowerCase()}
          </div>
        ) : (
          <>
            {amount && asset && (
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
            {username && (
              <div style={{ fontSize: 32, color: TEXT_SECONDARY, marginTop: 8 }}>
                to{" "}
                <span style={{ color: TEXT_PRIMARY, fontWeight: 700 }}>
                  @{username}
                </span>
              </div>
            )}
          </>
        )}

        {/* Footer */}
        <div
          style={{
            marginTop: 40,
            fontSize: 18,
            color: TEXT_SECONDARY,
          }}
        >
          Powered by Stellar Network
        </div>
      </div>
    </div>
  );
}

function renderProfileImage(params: OgParams) {
  const { username } = params;
  const initial = username?.[0]?.toUpperCase() ?? "?";

  return (
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
      {/* Glow */}
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
      <div style={{ fontSize: 60, fontWeight: 900, color: TEXT_PRIMARY, marginBottom: 16 }}>
        @{username ?? "unknown"}
      </div>

      {/* CTA */}
      <div style={{ fontSize: 28, color: TEXT_SECONDARY, marginBottom: 40 }}>
        Send a payment on Stellar
      </div>

      {/* Brand */}
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
  );
}

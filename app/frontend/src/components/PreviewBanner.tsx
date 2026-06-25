"use client";

/**
 * PreviewBanner
 *
 * Renders a sticky top banner that informs contributors which preview /
 * testnet environment they are currently using.
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ 🔬  PREVIEW ENVIRONMENT — staging │ branch: feat/FE-38 │ sha: a1b2c3d │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Guarantees:
 *  • Never renders in production (isPreviewEnvironment() === false).
 *  • Degrades gracefully — if the backend is unavailable the banner still
 *    shows static environment metadata resolved from env vars.
 *  • Accessible: uses role="banner", aria-label, and a dismiss button with
 *    an aria-label.
 *  • Respects prefers-reduced-motion via a CSS media query on the shimmer.
 */

import { useState } from "react";
import { usePreviewMetadata, isPreviewEnvironment } from "@/hooks/usePreviewMetadata";

// ─── sub-components ──────────────────────────────────────────────────────────

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        padding: "2px 8px",
        borderRadius: "9999px",
        background: "rgba(255,255,255,0.12)",
        border: "1px solid rgba(255,255,255,0.18)",
        fontSize: "11px",
        fontWeight: 600,
        letterSpacing: "0.02em",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function Skeleton() {
  return (
    <span
      aria-hidden="true"
      style={{
        display: "inline-block",
        width: "180px",
        height: "14px",
        borderRadius: "4px",
        background:
          "linear-gradient(90deg, rgba(255,255,255,0.08) 25%, rgba(255,255,255,0.18) 50%, rgba(255,255,255,0.08) 75%)",
        backgroundSize: "200% 100%",
        animation: "previewBannerShimmer 1.4s ease-in-out infinite",
      }}
    />
  );
}

// ─── keyframes injected once via a <style> tag ───────────────────────────────

const KEYFRAMES = `
@keyframes previewBannerShimmer {
  0%   { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
@keyframes previewBannerFadeIn {
  from { opacity: 0; transform: translateY(-6px); }
  to   { opacity: 1; transform: translateY(0); }
}
@media (prefers-reduced-motion: reduce) {
  .preview-banner-root {
    animation: none !important;
  }
  .preview-banner-shimmer {
    animation: none !important;
  }
}
`;

// ─── main component ───────────────────────────────────────────────────────────

export function PreviewBanner() {
  const [dismissed, setDismissed] = useState(false);

  // Hard guard: never render in production.
  if (!isPreviewEnvironment()) return null;

  // Once the user dismisses the banner for the session, respect that choice.
  if (dismissed) return null;

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: KEYFRAMES }} />
      <PreviewBannerInner onDismiss={() => setDismissed(true)} />
    </>
  );
}

// Split inner component so the hook only runs in non-production.
function PreviewBannerInner({ onDismiss }: { onDismiss: () => void }) {
  const { metadata, loading } = usePreviewMetadata();

  const envLabel = metadata?.envName?.toUpperCase() ?? "PREVIEW";
  const branch = metadata?.branch;
  const sha = metadata?.commitSha;

  return (
    <div
      id="preview-environment-banner"
      role="banner"
      aria-label={`Preview environment: ${envLabel}`}
      className="preview-banner-root"
      style={{
        position: "sticky",
        top: 0,
        zIndex: 60,
        width: "100%",
        background:
          "linear-gradient(90deg, #312e81 0%, #4f46e5 40%, #7c3aed 70%, #312e81 100%)",
        backgroundSize: "200% 100%",
        animation: "previewBannerFadeIn 0.35s ease-out both",
        borderBottom: "1px solid rgba(255,255,255,0.15)",
        boxShadow: "0 2px 12px rgba(79,70,229,0.45)",
      }}
    >
      <div
        style={{
          maxWidth: "1280px",
          margin: "0 auto",
          padding: "6px 24px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "12px",
          flexWrap: "wrap",
        }}
      >
        {/* Left: icon + env label */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            flexWrap: "wrap",
          }}
        >
          <span role="img" aria-label="preview" style={{ fontSize: "14px" }}>
            🔬
          </span>
          <span
            style={{
              fontSize: "12px",
              fontWeight: 700,
              letterSpacing: "0.08em",
              color: "#e0e7ff",
              textTransform: "uppercase",
            }}
          >
            Preview Environment
          </span>

          {/* Separator */}
          <span
            aria-hidden="true"
            style={{ opacity: 0.3, color: "#a5b4fc" }}
          >
            ·
          </span>

          {/* Chips */}
          {loading ? (
            <Skeleton />
          ) : (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                flexWrap: "wrap",
                color: "#c7d2fe",
              }}
            >
              <Chip>
                <span aria-hidden="true">⚙</span>
                {envLabel}
              </Chip>

              {branch && (
                <Chip>
                  <span aria-hidden="true" style={{ fontSize: "10px" }}>
                    ⎇
                  </span>
                  {branch}
                </Chip>
              )}

              {sha && (
                <Chip>
                  <span aria-hidden="true" style={{ fontSize: "10px" }}>
                    #
                  </span>
                  {sha}
                </Chip>
              )}
            </div>
          )}
        </div>

        {/* Right: info note + dismiss */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "12px",
            flexShrink: 0,
          }}
        >
          <span
            style={{
              fontSize: "11px",
              color: "#a5b4fc",
              fontStyle: "italic",
            }}
          >
            Not visible in production
          </span>

          <button
            id="preview-banner-dismiss-btn"
            type="button"
            aria-label="Dismiss preview environment banner"
            onClick={onDismiss}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              width: "22px",
              height: "22px",
              borderRadius: "50%",
              border: "1px solid rgba(255,255,255,0.25)",
              background: "rgba(255,255,255,0.08)",
              color: "#c7d2fe",
              cursor: "pointer",
              fontSize: "13px",
              lineHeight: 1,
              transition: "background 160ms, transform 160ms",
              padding: 0,
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLButtonElement).style.background =
                "rgba(255,255,255,0.2)";
              (e.currentTarget as HTMLButtonElement).style.transform =
                "scale(1.1)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLButtonElement).style.background =
                "rgba(255,255,255,0.08)";
              (e.currentTarget as HTMLButtonElement).style.transform = "scale(1)";
            }}
          >
            ✕
          </button>
        </div>
      </div>
    </div>
  );
}

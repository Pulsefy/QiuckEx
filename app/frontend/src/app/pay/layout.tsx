/**
 * Server-side layout for /pay — generates OpenGraph metadata for payment links.
 *
 * This file intentionally has NO "use client" directive so Next.js can call
 * generateMetadata() at request time and inject the correct <meta> tags before
 * the HTML is sent to the browser (and to social-media crawlers).
 *
 * The client-side page.tsx handles all interactive state; this layout only
 * contributes <head> metadata.
 */

import type { Metadata } from "next";
import {
  fetchPaymentMeta,
  buildPaymentTitle,
  buildPaymentDescription,
  getSiteUrl,
  DEFAULT_OG_IMAGE,
  FALLBACK_PAYMENT_METADATA,
  SITE_NAME,
} from "@/lib/og-metadata";

interface PayLayoutProps {
  children: React.ReactNode;
  // Next.js passes searchParams to layouts in the App Router
  // via the page's own props, but we can read them here via the
  // generateMetadata signature.
}

interface GenerateMetadataProps {
  searchParams: Promise<{
    username?: string;
    amount?: string;
    asset?: string;
    memo?: string;
    acceptedAssets?: string;
  }>;
}

export async function generateMetadata({
  searchParams,
}: GenerateMetadataProps): Promise<Metadata> {
  const params = await searchParams;
  const { username, amount, asset, memo, acceptedAssets } = params;

  const siteUrl = getSiteUrl();

  // Build the canonical URL for this payment link (safe — no private data)
  const canonicalParams = new URLSearchParams();
  if (username) canonicalParams.set("username", username);
  if (amount) canonicalParams.set("amount", amount);
  if (asset && asset !== "XLM") canonicalParams.set("asset", asset);
  if (memo) canonicalParams.set("memo", memo);
  if (acceptedAssets) canonicalParams.set("acceptedAssets", acceptedAssets);
  const canonicalUrl = `${siteUrl}/pay?${canonicalParams.toString()}`;

  // Guard: missing required params → safe fallback
  if (!username || !amount) {
    return buildFallbackMetadata(siteUrl, canonicalUrl);
  }

  // Fetch safe metadata from the backend
  const meta = await fetchPaymentMeta({ username, amount, asset, memo, acceptedAssets });

  // Backend unreachable or link not found → safe fallback
  if (!meta) {
    return buildFallbackMetadata(siteUrl, canonicalUrl);
  }

  const title = buildPaymentTitle(meta);
  const description = buildPaymentDescription(meta);

  // Build dynamic OG image URL with safe params only
  const ogImageParams = new URLSearchParams({ type: "payment" });
  ogImageParams.set("username", meta.username);
  if (meta.amount) ogImageParams.set("amount", meta.amount);
  ogImageParams.set("asset", meta.asset);
  ogImageParams.set("state", meta.state);
  const dynamicOgImage = `${siteUrl}/api/og?${ogImageParams.toString()}`;

  return {
    title: `${title} — ${SITE_NAME}`,
    description,
    alternates: {
      canonical: canonicalUrl,
    },
    openGraph: {
      type: "website",
      siteName: SITE_NAME,
      title,
      description,
      url: canonicalUrl,
      images: [
        {
          url: dynamicOgImage,
          width: 1200,
          height: 630,
          alt: title,
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      site: "@quickex",
      title,
      description,
      images: [dynamicOgImage],
    },
    // Prevent crawlers from indexing paid/expired/refunded links
    robots:
      meta.state === "ACTIVE" || meta.state === "DRAFT"
        ? { index: false, follow: false } // payment links are not meant to be indexed
        : { index: false, follow: false },
  };
}

function buildFallbackMetadata(siteUrl: string, canonicalUrl: string): Metadata {
  const ogImage = `${siteUrl}${DEFAULT_OG_IMAGE}`;
  return {
    title: `${FALLBACK_PAYMENT_METADATA.title} — ${SITE_NAME}`,
    description: FALLBACK_PAYMENT_METADATA.description,
    alternates: { canonical: canonicalUrl },
    openGraph: {
      type: "website",
      siteName: SITE_NAME,
      title: FALLBACK_PAYMENT_METADATA.title,
      description: FALLBACK_PAYMENT_METADATA.description,
      url: canonicalUrl,
      images: [{ url: ogImage, width: 1200, height: 630, alt: SITE_NAME }],
    },
    twitter: {
      card: "summary_large_image",
      site: "@quickex",
      title: FALLBACK_PAYMENT_METADATA.title,
      description: FALLBACK_PAYMENT_METADATA.description,
      images: [ogImage],
    },
    robots: { index: false, follow: false },
  };
}

export default function PayLayout({ children }: PayLayoutProps) {
  // This layout adds no visual chrome — it only contributes <head> metadata.
  return <>{children}</>;
}

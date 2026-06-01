/**
 * Server-side layout for /[username] — generates OpenGraph metadata for public profiles.
 *
 * No "use client" directive — this runs on the server so Next.js can inject
 * correct <meta> tags before the HTML reaches the browser / social crawlers.
 */

import type { Metadata } from "next";
import { getSiteUrl, DEFAULT_OG_IMAGE, SITE_NAME, SITE_DESCRIPTION } from "@/lib/og-metadata";

interface UsernameLayoutProps {
  children: React.ReactNode;
  params: Promise<{ username: string }>;
}

interface GenerateMetadataProps {
  params: Promise<{ username: string }>;
}

export async function generateMetadata({
  params,
}: GenerateMetadataProps): Promise<Metadata> {
  const { username } = await params;
  const siteUrl = getSiteUrl();

  // Sanitise: only allow alphanumeric + underscore + hyphen (Stellar username rules)
  const safeUsername = username?.replace(/[^\w-]/g, "").slice(0, 64) ?? "";

  if (!safeUsername) {
    return buildProfileFallback(siteUrl);
  }

  const canonicalUrl = `${siteUrl}/${safeUsername}`;

  // Build dynamic OG image URL
  const ogImageParams = new URLSearchParams({ type: "profile", username: safeUsername });
  const dynamicOgImage = `${siteUrl}/api/og?${ogImageParams.toString()}`;

  const title = `@${safeUsername} — Pay with QuickEx`;
  const description = `Send a payment to @${safeUsername} on the Stellar network using QuickEx. Fast, private, and fee-efficient.`;

  return {
    title: `${title} | ${SITE_NAME}`,
    description,
    alternates: {
      canonical: canonicalUrl,
    },
    openGraph: {
      type: "profile",
      siteName: SITE_NAME,
      title,
      description,
      url: canonicalUrl,
      images: [
        {
          url: dynamicOgImage,
          width: 1200,
          height: 630,
          alt: `${safeUsername} on QuickEx`,
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
    // Public profiles are indexable
    robots: { index: true, follow: true },
  };
}

function buildProfileFallback(siteUrl: string): Metadata {
  const ogImage = `${siteUrl}${DEFAULT_OG_IMAGE}`;
  return {
    title: `Profile not found — ${SITE_NAME}`,
    description: SITE_DESCRIPTION,
    openGraph: {
      type: "website",
      siteName: SITE_NAME,
      title: `Profile not found — ${SITE_NAME}`,
      description: SITE_DESCRIPTION,
      images: [{ url: ogImage, width: 1200, height: 630, alt: SITE_NAME }],
    },
    twitter: {
      card: "summary_large_image",
      site: "@quickex",
      title: `Profile not found — ${SITE_NAME}`,
      description: SITE_DESCRIPTION,
      images: [ogImage],
    },
    robots: { index: false, follow: false },
  };
}

export default function UsernameLayout({ children }: UsernameLayoutProps) {
  return <>{children}</>;
}

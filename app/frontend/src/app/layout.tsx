import type { Metadata } from "next";
import { Header } from "@/components/Header";
import { NotificationCenterProvider } from "@/components/NotificationCenterProvider";
import { ErrorReportingShell } from "@/components/ErrorReportingShell";
import "./globals.css";

const siteUrl =
  process.env.NEXT_PUBLIC_SITE_URL?.replace(/\/$/, "") ?? "https://quickex.to";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: "QuickEx",
    template: "%s | QuickEx",
  },
  description: "Privacy-focused payments on Stellar",
  applicationName: "QuickEx",
  keywords: ["Stellar", "payments", "crypto", "XLM", "USDC", "payment link"],
  authors: [{ name: "Pulsefy" }],
  creator: "Pulsefy",
  openGraph: {
    type: "website",
    siteName: "QuickEx",
    title: "QuickEx — Privacy-focused payments on Stellar",
    description: "Privacy-focused payments on Stellar",
    url: siteUrl,
    images: [
      {
        url: "/api/og",
        width: 1200,
        height: 630,
        alt: "QuickEx — Privacy-focused payments on Stellar",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    site: "@quickex",
    title: "QuickEx — Privacy-focused payments on Stellar",
    description: "Privacy-focused payments on Stellar",
    images: ["/api/og"],
  },
  robots: {
    index: true,
    follow: true,
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-neutral-950 text-white antialiased">
        <NotificationCenterProvider>
          <Header />
          <ErrorReportingShell>
            <main
              id="main-content"
              tabIndex={-1}
              className="min-h-screen container mx-auto px-6 py-10 focus:outline-none"
            >
              {children}
            </main>
          </ErrorReportingShell>

          <footer className="container mx-auto border-t border-white/5 px-6 py-12 text-sm text-neutral-400">
            <div className="flex flex-col items-center justify-between gap-6 md:flex-row">
              <p>Copyright 2026 QuickEx Platform. Built by Pulsefy.</p>
              <div className="flex gap-8 underline decoration-white/10 underline-offset-4 hover:decoration-white/20">
                <a
                  href="https://github.com/pulsefy/QuickEx"
                  target="_blank"
                  rel="noreferrer"
                >
                  GitHub
                </a>
                <a href="#">Terms</a>
                <a href="#">Privacy</a>
              </div>
            </div>
          </footer>
        </NotificationCenterProvider>
      </body>
    </html>
  );
}

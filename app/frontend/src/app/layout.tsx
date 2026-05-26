import type { Metadata } from "next";
import { Header } from "@/components/Header";
import { NotificationCenterProvider } from "@/components/NotificationCenterProvider";
import { ErrorReportingShell } from "@/components/ErrorReportingShell";
import "./globals.css";

export const metadata: Metadata = {
  title: "QuickEx",
  description: "Privacy-focused payments on Stellar",
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

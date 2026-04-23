import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Header } from "@/components/Header";
import i18n from '@/lib/i18n';

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

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
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-neutral-950 text-white`}
      >
        <Header />
        <main className="min-h-screen container mx-auto px-6 py-10">
          {children}
        </main>

        <footer className="container mx-auto px-6 py-12 border-t border-white/5 text-neutral-500 text-sm">
          <div className="flex flex-col md:flex-row justify-between items-center gap-6">
            <p>© 2026 QuickEx Platform. Built by Pulsefy.</p>
            <div className="flex gap-8 underline underline-offset-4 decoration-white/10 hover:decoration-white/20">
              <a href="https://github.com/pulsefy/QuickEx" target="_blank">
                GitHub
              </a>
              <a href="#">Terms</a>
              <a href="#">Privacy</a>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}

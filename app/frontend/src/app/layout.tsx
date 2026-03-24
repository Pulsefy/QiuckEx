import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import Link from "next/link";
import { NetworkBadge } from "@/components/NetworkBadge";
import { SearchBar } from "@/components/SearchBar";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "QuickEx",
  description: "Privacy-focused payments on Stellar",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased bg-neutral-950 text-white`}>
         
        
        <header className="border-b border-white/5 bg-neutral-950/60 backdrop-blur-xl sticky top-0 z-50">
          <nav className="container mx-auto px-6 py-4 flex justify-between items-center gap-4">
            <Link href="/" className="flex items-center gap-2 shrink-0 lg:mr-4">
              <div className="w-8 h-8 bg-indigo-500 rounded-lg flex items-center justify-center font-bold italic">
                Q
              </div>
              <span className="text-xl font-bold tracking-tight hidden lg:block">QuickEx</span>
            </Link>
            
            <div className="flex-1 max-w-md mx-2 md:mx-4">
              <SearchBar />
            </div>

            <div className="hidden md:flex items-center gap-6 text-sm text-neutral-400 font-medium shrink-0 ml-2">
              <Link href="/discovery" className="hover:text-white transition">Discovery</Link>
              <Link href="/dashboard" className="hover:text-white transition">Dashboard</Link>
              <Link href="/generator" className="hover:text-white transition">Generator</Link>
            </div>

            <div className="hidden md:block shrink-0 ml-4">
              <NetworkBadge />
            </div>
           
            <div className="md:hidden flex items-center gap-4 text-neutral-400 shrink-0 ml-2">
              <NetworkBadge />
              <div className="text-2xl cursor-pointer">☰</div>
            </div>
          </nav>
        </header>

        
        <main className="min-h-screen container mx-auto px-6 py-10">
          {children}
        </main>

       
        <footer className="container mx-auto px-6 py-12 border-t border-white/5 text-neutral-500 text-sm">
          <div className="flex flex-col md:flex-row justify-between items-center gap-6">
            <p>© 2026 QuickEx Platform. Built by Pulsefy.</p>
            <div className="flex gap-8 underline underline-offset-4 decoration-white/10 hover:decoration-white/20">
              <a href="https://github.com/pulsefy/QuickEx" target="_blank">GitHub</a>
              <a href="#">Terms</a>
              <a href="#">Privacy</a>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}

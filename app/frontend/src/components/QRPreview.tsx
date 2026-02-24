"use client";

import { useEffect, useState } from "react";
import QRCode from "react-qr-code";

export function QRPreview({ value }: { value?: string }) {
  const isValid = Boolean(value);

  return (
    <div className="relative group">
      <div className="absolute -inset-10 bg-indigo-500/10 blur-[60px] rounded-full opacity-50 group-hover:opacity-80 transition-opacity" />
      
      <div className="relative w-full aspect-square bg-gradient-to-br from-white/10 to-white/[0.02] backdrop-blur-3xl rounded-[3rem] p-1 border border-white/10 shadow-2xl overflow-hidden group-hover:scale-[1.02] transition-all duration-500">

        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-indigo-500/5 to-transparent h-1/2 w-full -translate-y-full hover:animate-[scan_3s_linear_infinite]" />
        
        <div className="h-full w-full bg-black/40 rounded-[2.8rem] flex flex-col items-center justify-center p-12 border border-white/5">

          {/* QR CONTAINER */}
          <div className="relative p-6 bg-white rounded-3xl shadow-[0_0_30px_rgba(255,255,255,0.05)]">
            {isValid ? (
              <QRCode
                value={value!}
                size={200}
                bgColor="white"
                fgColor="black"
              />
            ) : (
              /* Show your original placeholder */
              <div className="w-48 h-48 border-4 border-dashed border-neutral-100/30 rounded-2xl flex flex-col items-center justify-center gap-4">
                <div className="w-12 h-12 bg-black rounded-lg flex items-center justify-center">
                  <div className="w-6 h-6 bg-indigo-500 rounded-sm animate-pulse" />
                </div>
                <div className="grid grid-cols-2 gap-1 opacity-20 capitalize">
                  <div className="w-4 h-4 bg-black rounded-sm" />
                  <div className="w-4 h-4 bg-black rounded-sm" />
                  <div className="w-4 h-4 bg-black rounded-sm" />
                  <div className="w-4 h-4 bg-black rounded-sm" />
                </div>
              </div>
            )}
          </div>

          <div className="mt-10 text-center space-y-2">
            <p className="text-xs font-black text-indigo-400 tracking-[0.3em] uppercase">
              Ready to Scan
            </p>
            <p className="text-sm text-neutral-500 font-medium">
              Point your wallet camera here
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
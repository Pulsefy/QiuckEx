"use client";

import React from 'react';

export default function OfflinePage() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center px-6">
      <div className="w-24 h-24 mb-8 bg-neutral-900 border border-white/10 rounded-3xl flex items-center justify-center shadow-2xl">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
          strokeWidth={1.5}
          stroke="currentColor"
          className="w-12 h-12 text-neutral-500"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M8.25 21v-4.875c0-.621.504-1.125 1.125-1.125h5.25c.621 0 1.125.504 1.125 1.125V21m0 0h4.5V3.545M12.75 21h7.5V10.75M2.25 21h1.5m18 0h-18M2.25 9l4.5-1.636M18.75 3l-1.5.545m0 6.205 3 1m1.5-1.5-1.5.545m-15 10.605V15M9 3.75 3 5.625v13.5L9 17.25m6-13.5 6 1.875v13.5L15 17.25m-6 0v-13.5"
          />
        </svg>
      </div>
      <h1 className="text-4xl font-bold text-white mb-4 bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
        You're Offline
      </h1>
      <p className="text-neutral-400 max-w-md mx-auto mb-8 text-lg">
        It looks like you've lost your connection. Don't worry, QuickEx is ready to resume once you're back online.
      </p>
      <button
        onClick={() => window.location.reload()}
        className="px-8 py-3 bg-white text-black font-bold rounded-xl hover:bg-neutral-200 transition-all transform hover:scale-105 active:scale-95 shadow-lg"
      >
        Retry Connection
      </button>
      
      <div className="mt-12 p-4 rounded-2xl bg-white/5 border border-white/5 backdrop-blur-sm">
        <p className="text-sm text-neutral-500">
          Tip: You can still use the app for some basic features if they were cached.
        </p>
      </div>
    </div>
  )
}

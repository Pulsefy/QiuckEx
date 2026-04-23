'use client'

import { useEffect, useState } from 'react'

export function PWAHandler() {
  const [installPrompt, setInstallPrompt] = useState<any>(null)
  const [isInstalled, setIsInstalled] = useState(false)
  const [showBanner, setShowBanner] = useState(false)

  useEffect(() => {
    // Register Service Worker
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker
        .register('/sw.js')
        .then((reg) => {
          console.log('SW registered', reg)
          
          reg.addEventListener('updatefound', () => {
            const newWorker = reg.installing;
            newWorker?.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                // New content is available; please refresh.
                if (confirm('A new version of QuickEx is available. Refresh now?')) {
                  window.location.reload();
                }
              }
            });
          });
        })
        .catch((err) => console.error('SW registration failed', err))
    }

    // Check if already installed
    if (window.matchMedia('(display-mode: standalone)').matches) {
      setIsInstalled(true)
    }

    const handler = (e: any) => {
      e.preventDefault()
      setInstallPrompt(e)
      setShowBanner(true)
    }

    window.addEventListener('beforeinstallprompt', handler)

    window.addEventListener('appinstalled', () => {
      setIsInstalled(true)
      setShowBanner(false)
      setInstallPrompt(null)
    })

    return () => window.removeEventListener('beforeinstallprompt', handler)
  }, [])

  const handleInstall = async () => {
    if (!installPrompt) return
    installPrompt.prompt()
    const { outcome } = await installPrompt.userChoice
    if (outcome === 'accepted') {
      setShowBanner(false)
    }
  }

  if (!showBanner || isInstalled) return null

  return (
    <div className="fixed bottom-6 left-6 right-6 md:left-auto md:right-8 md:w-96 z-50 animate-in fade-in slide-in-from-bottom-5 duration-500">
      <div className="bg-neutral-900 border border-white/10 rounded-2xl p-5 shadow-2xl backdrop-blur-xl">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-purple-500 to-cyan-500 flex items-center justify-center flex-shrink-0 shadow-lg shadow-purple-500/20">
            <svg viewBox="0 0 24 24" className="w-6 h-6 text-white fill-current">
               <path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/>
            </svg>
          </div>
          <div className="flex-1">
            <h3 className="font-semibold text-white">Install QuickEx App</h3>
            <p className="text-sm text-neutral-400 mt-1">
              Add QuickEx to your home screen for a faster, offline-ready experience.
            </p>
            <div className="flex gap-3 mt-4">
              <button
                onClick={handleInstall}
                className="flex-1 bg-white text-black text-sm font-bold py-2.5 rounded-lg hover:bg-neutral-200 transition-colors"
              >
                Install Now
              </button>
              <button
                onClick={() => setShowBanner(false)}
                className="px-4 py-2.5 text-sm font-medium text-neutral-400 hover:text-white transition-colors"
              >
                Later
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

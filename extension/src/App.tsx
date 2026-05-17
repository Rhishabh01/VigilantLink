import { useState, useEffect, useCallback } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import SafetyScoreCard from './components/SafetyScoreCard'
import WarningBanner from './components/WarningBanner'
import VirusTotalCard from './components/VirusTotalCard'
import WebsitePreview from './components/WebsitePreview'
import ReasonsSection from './components/ReasonsSection'
import FooterDisclaimer from './components/FooterDisclaimer'
import LoadingSkeleton from './components/LoadingSkeleton'
import type { SafetyData, VirusTotalData, WebsitePreviewData } from './types'

interface AnalysisState {
  safety?: SafetyData
  virustotal?: VirusTotalData
  website?: WebsitePreviewData
  loading: boolean
}

function Header() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('vigilantlink-theme')
      if (stored === 'light' || stored === 'dark') return stored
      return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
    }
    return 'dark'
  })

  useEffect(() => {
    localStorage.setItem('vigilantlink-theme', theme)
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])

  return (
    <motion.header
      initial={{ opacity: 0, y: -4 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex items-center justify-between px-5 py-3 border-b border-border"
    >
      <div className="flex items-center gap-2.5">
        <img
          src="icons/icon48.png"
          alt="VigilantLink"
          className="w-5 h-5 rounded object-contain flex-shrink-0"
        />
        <h1 className="text-[13px] font-semibold tracking-tight">VigilantLink</h1>
      </div>

      <button
        onClick={() => setTheme(t => (t === 'dark' ? 'light' : 'dark'))}
        className="p-1.5 text-muted hover:text-text rounded-lg hover:bg-border transition-colors focus:outline-none focus:ring-2 focus:ring-accent/40"
        aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
        title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      >
        {theme === 'dark' ? (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="5" />
            <line x1="12" y1="1" x2="12" y2="3" />
            <line x1="12" y1="21" x2="12" y2="23" />
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
            <line x1="1" y1="12" x2="3" y2="12" />
            <line x1="21" y1="12" x2="23" y2="12" />
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
          </svg>
        ) : (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
          </svg>
        )}
      </button>
    </motion.header>
  )
}

function LoadingView() {
  return (
    <div className="px-4 py-3 space-y-3">
      <LoadingSkeleton />
      <LoadingSkeleton />
      <LoadingSkeleton type="image" />
    </div>
  )
}

function EmptyView() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="px-5 py-12 text-center"
    >
      <svg
        width="32"
        height="32"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="mx-auto mb-3 text-dim"
        aria-hidden="true"
      >
        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
      </svg>
      <p className="text-[13px] text-muted font-medium">No analysis data</p>
      <p className="text-[11px] text-dim mt-1">
        Hover over a link to analyze its safety.
      </p>
    </motion.div>
  )
}

export default function App() {
  const [state, setState] = useState<AnalysisState>({ loading: true })
  const [error, setError] = useState<string | null>(null)

  const fetchAnalysis = useCallback(async () => {
    setState(prev => ({ ...prev, loading: true }))
    setError(null)

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (!tab?.id || !tab.url) {
        setState({ loading: false })
        return
      }

      const url = new URL(tab.url)
      const isBrowserPage = url.protocol === 'chrome:' || url.protocol === 'chrome-extension:'

      if (isBrowserPage) {
        setState({ loading: false })
        return
      }

      const response = await chrome.runtime.sendMessage({
        action: 'analyze_link',
        url: tab.url,
        cache_only: true,
      })

      if (response?.success) {
        const data = response.data

        if (data.sec) {
          const riskScore = Math.max(0, Math.min(100, 100 - (data.sec.rs || 0)))

          let description = 'No significant security threats detected.'
          if (data.sec.tt) {
            description = `${data.sec.tt}. Please evaluate the forensic signals below.`
          } else if (riskScore < 40) {
            description = 'Multiple potential security anomalies detected. Proceed with caution.'
          } else if (riskScore < 70) {
            description = 'Heuristic analysis suggests elevated risks. General caution is advised.'
          }

          const safety: SafetyData = {
            score: riskScore,
            maxScore: 100,
            label: riskScore >= 70 ? 'high' : riskScore >= 40 ? 'medium' : 'low',
            description,
            reasons: data.sec.r || [],
            verdict: data.sec.v || 'green',
          }

          const vf = data.sec.vf !== undefined ? data.sec.vf : null
          const tv = data.sec.tv !== undefined ? data.sec.tv : 0

          let domain = ''
          try {
            domain = new URL(data.furl || tab.url).hostname
          } catch (e) {
            domain = tab.url
          }

          const virustotal: VirusTotalData = {
            detections: vf !== null ? vf : 0,
            total: tv > 0 ? tv : 70,
            permalink: domain ? `https://www.virustotal.com/gui/domain/${domain}` : 'https://www.virustotal.com',
            available: vf !== null && tv > 0,
          }

          const website: WebsitePreviewData = {
            title: data.t || data.title || tab.title || '',
            url: data.furl || tab.url,
            screenshotUrl: data.ss || data.img || undefined,
          }

          setState({ safety, virustotal, website, loading: false })
        } else {
          setState({ loading: false })
        }
      } else {
        setState({ loading: false })
      }
    } catch (err) {
      console.error('VigilantLink popup error:', err)
      setError(err instanceof Error ? err.message : 'Failed to load analysis data')
      setState(prev => ({ ...prev, loading: false }))
    }
  }, [])

  useEffect(() => {
    fetchAnalysis()
  }, [fetchAnalysis])

  const { safety, virustotal, website, loading } = state

  return (
    <div className="flex flex-col min-h-[400px] bg-bg text-text">
      <Header />

      <div className="flex-grow overflow-y-auto">
        <AnimatePresence mode="wait">
          {loading ? (
            <motion.div
              key="loading"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <LoadingView />
            </motion.div>
          ) : error ? (
            <motion.div
              key="error"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="px-5 py-10 text-center"
            >
              <p className="text-[13px] text-red-400 font-medium">Error loading analysis</p>
              <p className="text-[11px] text-dim mt-1">{error}</p>
            </motion.div>
          ) : !safety ? (
            <EmptyView />
          ) : (
            <motion.div
              key="content"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="px-4 py-3 space-y-3"
            >
              <SafetyScoreCard data={safety} />
              {virustotal && virustotal.available && virustotal.detections > 0 && (
                <WarningBanner detections={virustotal.detections} />
              )}
              <VirusTotalCard data={virustotal} />
              <WebsitePreview data={website} />
              <ReasonsSection reasons={safety.reasons} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <FooterDisclaimer />
    </div>
  )
}

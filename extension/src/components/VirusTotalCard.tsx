import { useState, useRef, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import { CardSkeleton } from './LoadingSkeleton'
import type { VirusTotalData } from '../types'

interface VirusTotalCardProps {
  data?: VirusTotalData
  loading?: boolean
}

function VirusTotalIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      className="flex-shrink-0"
    >
      <rect x="2" y="2" width="20" height="20" rx="4" fill="#394EFF" />
      <path
        d="M12 6L7 12H10V18H14V12H17L12 6Z"
        fill="white"
      />
    </svg>
  )
}

function ExternalLinkIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  )
}

function InfoIcon({ className }: { className?: string }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  )
}

function getDetectionColor(detections: number, total: number): string {
  const ratio = detections / total
  if (ratio >= 0.5) return 'text-red-400'
  if (ratio >= 0.2) return 'text-amber-400'
  return 'text-emerald-400'
}

export default function VirusTotalCard({ data, loading }: VirusTotalCardProps) {
  const [tooltipOpen, setTooltipOpen] = useState(false)
  const tooltipRef = useRef<HTMLDivElement>(null)
  const btnRef = useRef<HTMLButtonElement>(null)

  const closeTooltip = useCallback(() => setTooltipOpen(false), [])

  useEffect(() => {
    if (!tooltipOpen) return
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        closeTooltip()
        btnRef.current?.focus()
      }
    }
    const handleClickOutside = (e: MouseEvent) => {
      if (tooltipRef.current && !tooltipRef.current.contains(e.target as Node) &&
          btnRef.current && !btnRef.current.contains(e.target as Node)) {
        closeTooltip()
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    document.addEventListener('mousedown', handleClickOutside)
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [tooltipOpen, closeTooltip])

  if (loading || !data) {
    return <CardSkeleton />
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: 'easeOut', delay: 0.1 }}
      className="bg-surface border border-border rounded-xl p-4 shadow-lg"
      role="region"
      aria-label="VirusTotal information"
    >
      <div className="flex items-center gap-2 mb-3">
        <VirusTotalIcon />
        <span className="text-[12px] font-semibold text-text-secondary tracking-tight">
          VirusTotal (via API)
        </span>
        <div className="relative ml-auto">
          <button
            ref={btnRef}
            onClick={() => setTooltipOpen(v => !v)}
            onMouseEnter={() => setTooltipOpen(true)}
            onMouseLeave={() => setTooltipOpen(false)}
            className="text-dim hover:text-text-secondary transition-colors cursor-pointer focus:outline-none focus:ring-2 focus:ring-accent/40 rounded-sm"
            aria-label="About VirusTotal data source"
            aria-expanded={tooltipOpen}
            type="button"
          >
            <InfoIcon />
          </button>
          {tooltipOpen && (
            <div
              ref={tooltipRef}
              role="tooltip"
              className="absolute right-0 top-full mt-1.5 w-52 p-2 bg-surface-light border border-border rounded-lg text-[11px] text-muted leading-relaxed shadow-lg z-10"
              onMouseEnter={() => setTooltipOpen(true)}
              onMouseLeave={() => setTooltipOpen(false)}
            >
              VirusTotal provides third-party vendor detection data. This is supplementary information and not VigilantLink's own verdict.
            </div>
          )}
        </div>
      </div>

      <div className="flex items-baseline gap-1 mb-0.5">
        <span className={`text-[28px] font-bold leading-none tabular-nums ${getDetectionColor(data.detections, data.total)}`}>
          {data.available ? data.detections : '--'}
        </span>
        <span className="text-[14px] font-semibold text-muted">/ {data.total}</span>
      </div>

      <p className="text-[11px] text-dim mb-3">
        {data.available
          ? 'vendors flagged this URL'
          : 'VirusTotal data unavailable'}
      </p>

      {data.available && data.permalink && (
        <motion.a
          whileHover={{ x: 2 }}
          href={data.permalink}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-[12px] font-medium text-accent hover:text-accent-hover transition-colors focus:outline-none focus:ring-2 focus:ring-accent/40 focus:ring-offset-2 focus:ring-offset-surface rounded-md px-1 -ml-1"
          aria-label="View full VirusTotal report (opens in new tab)"
        >
          View full report
          <ExternalLinkIcon />
        </motion.a>
      )}

      {!data.available && (
        <p className="text-[11px] text-dim italic">
          Detection data could not be retrieved from VirusTotal at this time.
        </p>
      )}
    </motion.div>
  )
}

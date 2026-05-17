import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ImageSkeleton } from './LoadingSkeleton'
import type { WebsitePreviewData } from '../types'

interface WebsitePreviewProps {
  data?: WebsitePreviewData
  loading?: boolean
}

const SITE_PLACEHOLDER = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='400' height='220' viewBox='0 0 400 220'%3E%3Crect fill='%231e293b' width='400' height='220'/%3E%3Ctext x='200' y='110' text-anchor='middle' fill='%2364748b' font-family='Inter, sans-serif' font-size='14'%3EPreview unavailable%3C/text%3E%3C/svg%3E`

export default function WebsitePreview({ data, loading }: WebsitePreviewProps) {
  const [imageLoaded, setImageLoaded] = useState(false)
  const [imageError, setImageError] = useState(false)

  if (loading || !data) {
    return <ImageSkeleton />
  }

  const { title, url, screenshotUrl } = data

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: 'easeOut', delay: 0.2 }}
      className="bg-surface border border-border rounded-xl overflow-hidden shadow-lg"
      role="region"
      aria-label="Website preview"
    >
      <div className="p-3 border-b border-border">
        {title && (
          <p className="text-[13px] font-semibold text-text truncate mb-1" title={title}>
            {title}
          </p>
        )}
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="block text-[11px] text-accent hover:text-accent-hover truncate transition-colors focus:outline-none focus:ring-2 focus:ring-accent/40 focus:ring-offset-2 focus:ring-offset-surface rounded-sm"
          title={url}
          aria-label={`Destination URL: ${url}`}
        >
          {url}
        </a>
      </div>

      <div className="relative bg-bg/50">
        <AnimatePresence mode="wait">
          {!imageLoaded && !imageError && (
            <motion.div
              key="loading"
              initial={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0"
            >
              <div className="skeleton h-44 w-full rounded-none" />
            </motion.div>
          )}
        </AnimatePresence>

        {screenshotUrl && !imageError ? (
          <motion.img
            initial={{ opacity: 0 }}
            animate={{ opacity: imageLoaded ? 1 : 0 }}
            transition={{ duration: 0.4 }}
            src={screenshotUrl}
            alt={`Screenshot of ${title || url}`}
            className="w-full h-44 object-contain object-top"
            onLoad={() => setImageLoaded(true)}
            onError={() => setImageError(true)}
          />
        ) : (
          <img
            src={SITE_PLACEHOLDER}
            alt="Preview placeholder"
            className="w-full h-44 object-cover"
          />
        )}
      </div>
    </motion.div>
  )
}

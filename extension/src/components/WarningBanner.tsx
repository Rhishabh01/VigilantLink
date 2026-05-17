import { motion } from 'framer-motion'

interface WarningBannerProps {
  detections: number
}

export default function WarningBanner({ detections }: WarningBannerProps) {
  if (detections <= 0) return null

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      className="bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-xl p-3 flex items-start gap-2.5 shadow-sm"
      role="alert"
    >
      <svg
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="flex-shrink-0 mt-0.5"
        aria-hidden="true"
      >
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
      <div className="text-[12px] font-medium leading-normal">
        VirusTotal detections reported by {detections} vendor{detections > 1 ? 's' : ''}.
      </div>
    </motion.div>
  )
}

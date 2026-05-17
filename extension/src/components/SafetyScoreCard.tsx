import { motion } from 'framer-motion'
import StatusBadge from './StatusBadge'
import { CardSkeleton } from './LoadingSkeleton'
import type { SafetyData } from '../types'

interface SafetyScoreCardProps {
  data?: SafetyData
  loading?: boolean
}

function getScoreColor(score: number, maxScore: number): 'success' | 'warning' | 'info' {
  const ratio = score / maxScore
  if (ratio >= 0.7) return 'success'
  return 'warning'
}

function getBadgeLabel(score: number): string {
  if (score >= 70) return 'Appears Safe'
  if (score >= 40) return 'Potential Risk'
  return 'Use Caution'
}

function getBadgeVariant(score: number): 'success' | 'warning' | 'info' {
  if (score >= 70) return 'success'
  return 'warning'
}

export default function SafetyScoreCard({ data, loading }: SafetyScoreCardProps) {
  if (loading || !data) {
    return <CardSkeleton />
  }

  const { score, maxScore, description } = data
  const barWidth = (score / maxScore) * 100
  const colorVar = getScoreColor(score, maxScore)

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: 'easeOut' }}
      className="bg-surface border border-border rounded-xl p-4 shadow-lg"
      role="region"
      aria-label="Safety Score"
    >
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-[13px] font-semibold text-text tracking-tight">
          VigilantLink Safety Score
        </h2>
        <StatusBadge
          label={getBadgeLabel(score)}
          variant={getBadgeVariant(score)}
        />
      </div>

      <div className="flex items-baseline gap-1.5 mb-2">
        <span className="text-[12px] font-medium text-muted">Safety Score:</span>
        <motion.span
          key={score}
          initial={{ opacity: 0, y: -4 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-[28px] font-bold text-text leading-none tabular-nums"
        >
          {score}
        </motion.span>
        <span className="text-[14px] font-semibold text-dim">/ {maxScore}</span>
      </div>

      <div className="w-full h-1.5 bg-surface-light rounded-full overflow-hidden mb-2.5">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${barWidth}%` }}
          transition={{ duration: 0.6, ease: 'easeOut', delay: 0.15 }}
          className={`h-full rounded-full ${
            colorVar === 'success'
              ? 'bg-emerald-500'
              : 'bg-amber-500'
          }`}
        />
      </div>

      <p className="text-[12px] text-muted leading-relaxed">
        {description}
      </p>

      <p className="text-[10px] text-dim mt-2.5 leading-normal select-none">
        Analysis based on heuristic and external security signals.
      </p>
    </motion.div>
  )
}

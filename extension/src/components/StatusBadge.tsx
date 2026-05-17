import { motion } from 'framer-motion'

interface StatusBadgeProps {
  label: string
  variant: 'success' | 'warning' | 'info'
}

const variantStyles: Record<string, string> = {
  success: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
  warning: 'bg-amber-500/15 text-amber-400 border-amber-500/25',
  info: 'bg-blue-500/15 text-blue-400 border-blue-500/25',
}

const dotStyles: Record<string, string> = {
  success: 'bg-emerald-400',
  warning: 'bg-amber-400',
  info: 'bg-blue-400',
}

export default function StatusBadge({ label, variant }: StatusBadgeProps) {
  return (
    <motion.span
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.25, ease: 'easeOut' }}
      className={`
        inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full
        text-[11px] font-semibold uppercase tracking-[0.03em]
        border ${variantStyles[variant]}
      `}
      aria-label={`Status: ${label}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${dotStyles[variant]}`} />
      {label}
    </motion.span>
  )
}

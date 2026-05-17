import { motion } from 'framer-motion'

interface LoadingSkeletonProps {
  type?: 'card' | 'text' | 'image'
}

function Shimmer({ className }: { className?: string }) {
  return <div className={`skeleton rounded-lg ${className ?? ''}`} />
}

export function CardSkeleton() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="bg-surface border border-border rounded-xl p-4 space-y-3"
      role="status"
      aria-label="Loading content"
    >
      <div className="flex items-center justify-between">
        <Shimmer className="h-4 w-32" />
        <Shimmer className="h-5 w-20 rounded-full" />
      </div>
      <Shimmer className="h-8 w-24" />
      <Shimmer className="h-3 w-48" />
    </motion.div>
  )
}

export function ImageSkeleton() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="bg-surface border border-border rounded-xl overflow-hidden"
      role="status"
      aria-label="Loading preview"
    >
      <Shimmer className="h-40 w-full rounded-none" />
    </motion.div>
  )
}

export default function LoadingSkeleton({ type }: LoadingSkeletonProps) {
  if (type === 'image') return <ImageSkeleton />
  return <CardSkeleton />
}

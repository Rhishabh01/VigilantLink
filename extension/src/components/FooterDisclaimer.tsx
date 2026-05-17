import { motion } from 'framer-motion'

export default function FooterDisclaimer() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.3 }}
      className="px-5 py-3 border-t border-border mt-auto"
    >
      <p className="text-[10px] text-dim leading-normal text-center select-none">
        Analysis combines heuristic signals and external threat intelligence sources. Results are informational and should not be treated as definitive security guarantees.
      </p>
    </motion.div>
  )
}

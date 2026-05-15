import { motion } from 'framer-motion';

const VARIANTS = {
  safe: {
    label: 'Currently Appears Safe',
    bg: 'rgba(16, 185, 129, 0.15)',
    text: '#34d399',
    dot: '#34d399',
  },
  low: {
    label: 'Low Risk',
    bg: 'rgba(59, 130, 246, 0.15)',
    text: '#60a5fa',
    dot: '#60a5fa',
  },
  info: {
    label: 'No Major Threats Detected',
    bg: 'rgba(234, 179, 8, 0.15)',
    text: '#fbbf24',
    dot: '#fbbf24',
  },
};

export default function StatusBadge({ safe, riskScore }) {
  let variant;
  if (safe === true) {
    variant = VARIANTS.safe;
  } else if (riskScore != null && riskScore < 30) {
    variant = VARIANTS.low;
  } else {
    variant = VARIANTS.info;
  }

  return (
    <motion.span
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold tracking-wide"
      style={{ background: variant.bg, color: variant.text }}
      role="status"
      aria-label={variant.label}
    >
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{ background: variant.dot }}
      />
      {variant.label}
    </motion.span>
  );
}

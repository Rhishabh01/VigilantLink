import { motion } from 'framer-motion';
import StatusBadge from './StatusBadge';

export default function SafetyScoreCard({ riskScore, isSafe, loading }) {
  const safetyScore = riskScore != null ? Math.max(0, 100 - riskScore) : null;

  if (loading) {
    return (
      <div className="bg-[#1e293b] rounded-xl p-5 border border-white/5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="h-3 w-40 bg-white/10 rounded animate-pulse" />
        </div>
        <div className="flex items-end justify-between mb-3">
          <div className="flex items-baseline gap-1">
            <div className="h-10 w-20 bg-white/10 rounded animate-pulse" />
            <div className="h-5 w-12 bg-white/10 rounded animate-pulse" />
          </div>
          <div className="h-6 w-32 bg-white/10 rounded-full animate-pulse" />
        </div>
        <div className="h-3 w-52 bg-white/10 rounded animate-pulse" />
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="bg-[#1e293b] rounded-xl p-5 border border-white/5 shadow-lg"
    >
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-[0.06em]">
          VigilantLink Safety Score
        </h2>
      </div>

      <div className="flex items-end justify-between mb-2">
        <div className="flex items-baseline gap-1">
          <span className="text-4xl font-extrabold text-white tracking-tight">
            {safetyScore ?? '--'}
          </span>
          <span className="text-lg font-semibold text-slate-500">/ 100</span>
        </div>
        {isSafe != null && <StatusBadge safe={isSafe} riskScore={riskScore} />}
      </div>

      <p className="text-xs text-slate-400 leading-relaxed">
        No significant security threats detected.
      </p>
    </motion.div>
  );
}

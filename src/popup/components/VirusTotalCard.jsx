import { motion } from 'framer-motion';

function InfoIcon() {
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
      className="text-slate-500"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  );
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
  );
}

function ShieldIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="#60a5fa"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

export default function VirusTotalCard({ vendorFlags, totalVendors, vtReportUrl, loading }) {
  if (loading) {
    return (
      <div className="bg-[#1a2332] rounded-xl p-4 border border-white/5 shadow-sm">
        <div className="flex items-center gap-2 mb-3">
          <div className="w-4 h-4 bg-white/10 rounded animate-pulse" />
          <div className="h-3 w-40 bg-white/10 rounded animate-pulse" />
        </div>
        <div className="h-8 w-24 bg-white/10 rounded animate-pulse mb-2" />
        <div className="h-3 w-36 bg-white/10 rounded animate-pulse" />
      </div>
    );
  }

  const hasData = vendorFlags != null && totalVendors != null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: 0.1 }}
      className="bg-[#1a2332] rounded-xl p-4 border border-white/5 shadow-sm relative"
    >
      <div className="absolute -top-2 left-4 right-4 flex items-center gap-2">
        <div className="flex-1 h-px bg-white/5" />
        <span className="text-[10px] text-slate-600 uppercase tracking-wider font-medium px-2 bg-[#0b1121]">
          External Signal
        </span>
        <div className="flex-1 h-px bg-white/5" />
      </div>

      <div className="mt-2">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <ShieldIcon />
            <span className="text-sm font-semibold text-slate-300">
              VirusTotal
              <span className="text-xs text-slate-500 font-normal ml-1">(via API)</span>
            </span>
          </div>
          <span
            className="relative group"
            role="tooltip"
            aria-label="VirusTotal provides third-party vendor detection data. This is not VigilantLink's own verdict."
            tabIndex={0}
          >
            <InfoIcon />
            <span className="absolute right-0 top-6 w-56 p-2 bg-[#0f172a] border border-white/10 rounded-lg text-[11px] text-slate-400 leading-relaxed opacity-0 group-hover:opacity-100 group-focus:opacity-100 transition-opacity pointer-events-none z-10 shadow-xl">
              VirusTotal provides third-party vendor detection data. This is not VigilantLink's own security verdict.
            </span>
          </span>
        </div>

        {hasData ? (
          <>
            <div className="flex items-baseline gap-1 mb-1">
              <span className="text-2xl font-bold text-slate-200">
                {vendorFlags}
              </span>
              <span className="text-base font-semibold text-slate-500">/ {totalVendors}</span>
            </div>
            <p className="text-xs text-slate-500 mb-3">
              {vendorFlags === 1 ? 'vendor flagged' : 'vendors flagged'} this URL
            </p>
          </>
        ) : (
          <p className="text-sm text-slate-500 italic mb-3">
            VirusTotal data unavailable
          </p>
        )}

        {vtReportUrl && (
          <a
            href={vtReportUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 hover:text-blue-300 transition-colors py-1.5 px-3 rounded-lg border border-blue-400/20 hover:border-blue-400/40 bg-blue-400/5 hover:bg-blue-400/10"
            aria-label="View full VirusTotal report in a new tab"
          >
            View full report
            <ExternalLinkIcon />
          </a>
        )}
      </div>
    </motion.div>
  );
}

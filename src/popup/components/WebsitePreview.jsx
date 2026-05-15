import { motion } from 'framer-motion';

export default function WebsitePreview({ title, url, screenshot, loading }) {
  if (loading) {
    return (
      <div className="bg-[#1e293b] rounded-xl border border-white/5 shadow-sm overflow-hidden">
        <div className="p-3 border-b border-white/5 space-y-1.5">
          <div className="h-3 w-44 bg-white/10 rounded animate-pulse" />
          <div className="h-3 w-60 bg-white/10 rounded animate-pulse" />
        </div>
        <div className="h-32 bg-white/5 animate-pulse" />
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: 0.2 }}
      className="bg-[#1e293b] rounded-xl border border-white/5 shadow-sm overflow-hidden"
    >
      <div className="p-3 border-b border-white/5 space-y-1">
        {title && (
          <p className="text-xs font-medium text-slate-300 truncate" title={title}>
            {title}
          </p>
        )}
        {url && (
          <p className="text-[11px] text-slate-500 truncate" title={url}>
            {url}
          </p>
        )}
      </div>

      <div className="relative bg-[#131d2f] h-32 flex items-center justify-center overflow-hidden">
        {screenshot ? (
          <img
            src={`data:image/png;base64,${screenshot}`}
            alt={`Screenshot of ${title || url}`}
            className="w-full h-full object-cover"
          />
        ) : (
          <div className="flex flex-col items-center gap-2 text-slate-600">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
              <circle cx="8.5" cy="8.5" r="1.5" />
              <polyline points="21 15 16 10 5 21" />
            </svg>
            <span className="text-[11px]">Preview unavailable</span>
          </div>
        )}
      </div>
    </motion.div>
  );
}

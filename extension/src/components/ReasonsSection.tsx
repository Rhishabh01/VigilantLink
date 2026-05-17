import { motion } from 'framer-motion'

interface ReasonsSectionProps {
  reasons?: string[]
}

const explanations: Record<string, string> = {
  'Punycode Homograph Attack': 'Punycode domain trick',
  'Typosquatting Detected': 'Possible impersonation attempt',
  'Excessive Redirect Chain': 'Suspicious redirect chain',
  'Connection is not encrypted': 'No encryption (HTTP)',
  'Invalid SSL certificate': 'Certificate error',
  'Suspicious Keywords': 'Suspicious content detected',
  'Synergy': 'High-risk combination',
  'Phishing keyword': 'Phishing attempt',
  'CRITICAL: Punycode': 'Punycode domain trick',
  'CRITICAL: Flagged': 'Flagged by security vendors',
  'CRITICAL: VirusTotal': 'Flagged by VirusTotal',
  'Flagged by': 'Flagged by vendors',
  'Recently issued SSL certificate': 'New SSL certificate',
  'Young SSL certificate': 'Young SSL certificate',
  'does not resolve': 'Domain invalid',
  'Suspicious TLD': 'Suspicious domain extension',
  'Uncertainty penalty': 'Limited security data',
}

function cleanExplanation(reason: string): string {
  for (const [key, value] of Object.entries(explanations)) {
    if (reason.includes(key)) return value
  }
  return reason.length > 40 ? reason.substring(0, 37) + '...' : reason
}

function getBadgeColor(reason: string): string {
  if (
    reason.includes('Punycode') ||
    reason.includes('Typosquatting') ||
    reason.includes('impersonation') ||
    reason.includes('Synergy') ||
    reason.includes('Homograph')
  ) {
    return 'bg-red-500/10 text-red-400 border-red-500/20'
  }
  if (
    reason.includes('Redirect') ||
    reason.includes('SSL') ||
    reason.includes('encryption') ||
    reason.includes('HTTP') ||
    reason.includes('Flagged') ||
    reason.includes('certificate')
  ) {
    return 'bg-amber-500/10 text-amber-400 border-amber-500/20'
  }
  return 'bg-slate-500/10 text-slate-400 border-slate-500/20'
}

export default function ReasonsSection({ reasons }: ReasonsSectionProps) {
  if (!reasons || reasons.length === 0) return null

  // Filter out any uncertainty penalty or timed out messages to keep the popup UI clean and concise
  const filteredReasons = reasons.filter(
    (r) => !r.includes('Uncertainty penalty') && !r.includes('timed out') && !r.includes('Limited security data')
  )

  if (filteredReasons.length === 0) return null

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: 0.15 }}
      className="bg-surface border border-border rounded-xl p-4 shadow-lg space-y-2.5"
    >
      <h3 className="text-[12px] font-semibold text-text-secondary tracking-tight">
        Forensic Signals
      </h3>
      <div className="flex flex-wrap gap-1.5" role="list" aria-label="Security analysis signals">
        {filteredReasons.map((reason, index) => (
          <span
            key={index}
            className={`px-2.5 py-0.5 rounded-full text-[10px] font-medium border ${getBadgeColor(reason)}`}
            title={reason}
            role="listitem"
          >
            {cleanExplanation(reason)}
          </span>
        ))}
      </div>
    </motion.div>
  )
}

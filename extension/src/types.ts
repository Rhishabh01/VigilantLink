export interface SafetyData {
  score: number
  maxScore: number
  label: 'low' | 'medium' | 'high'
  description: string
}

export interface VirusTotalData {
  detections: number
  total: number
  permalink: string
  available: boolean
}

export interface WebsitePreviewData {
  title: string
  url: string
  screenshotUrl?: string
}

export interface AnalysisData {
  safety: SafetyData
  virustotal: VirusTotalData
  website: WebsitePreviewData
  loading: boolean
}

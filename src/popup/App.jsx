import { useAnalysisData } from './hooks/useAnalysisData';
import SafetyScoreCard from './components/SafetyScoreCard';
import VirusTotalCard from './components/VirusTotalCard';
import WebsitePreview from './components/WebsitePreview';

export default function App() {
  const { data, loading, error, tabInfo, vtReportUrl } = useAnalysisData();

  const sec = data?.sec || {};
  const riskScore = sec.rs;
  const isSafe = sec.safe;
  const vendorFlags = sec.vf;
  const totalVendors = sec.tv;
  const screenshot = data?.ss;
  const title = data?.t || tabInfo.title;
  const url = data?.url || tabInfo.url;

  return (
    <div className="p-3 space-y-3">
      <header className="flex items-center gap-2.5 px-1 py-1">
        <img
          src="icons/icon48.png"
          alt="VigilantLink"
          className="w-5 h-5 rounded"
        />
        <h1 className="text-sm font-bold text-white">VigilantLink</h1>
      </header>

      {error && (
        <div
          className="bg-red-900/20 border border-red-500/20 rounded-xl p-3 text-xs text-red-400"
          role="alert"
        >
          {error}
        </div>
      )}

      <SafetyScoreCard
        riskScore={riskScore}
        isSafe={isSafe}
        loading={loading && !data}
      />

      <VirusTotalCard
        vendorFlags={vendorFlags}
        totalVendors={totalVendors}
        vtReportUrl={vtReportUrl}
        loading={loading && !data}
      />

      <WebsitePreview
        title={title}
        url={url}
        screenshot={screenshot}
        loading={loading && !data}
      />
    </div>
  );
}

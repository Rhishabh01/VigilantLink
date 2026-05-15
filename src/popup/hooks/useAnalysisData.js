import { useState, useEffect, useRef } from 'react';

const BACKEND_URL = 'https://extension-production-4bd4.up.railway.app';

async function pollDeepScan(requestId, signal) {
  const startTime = Date.now();
  const timeoutMs = 15000;
  const intervalMs = 1000;

  while (Date.now() - startTime < timeoutMs) {
    if (signal.aborted) return null;
    await new Promise(r => setTimeout(r, intervalMs));
    if (signal.aborted) return null;
    try {
      const response = await fetch(`${BACKEND_URL}/analyze/deep/${requestId}`, { signal });
      if (!response.ok) continue;
      const data = await response.json();
      if (data.s === 2) return data;
    } catch (e) {
      if (e.name === 'AbortError') return null;
    }
  }
  return null;
}

async function computeVtUrl(url) {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(url);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return `https://www.virustotal.com/gui/url/${hashHex}`;
  } catch {
    return null;
  }
}

export function useAnalysisData() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tabInfo, setTabInfo] = useState({ title: '', url: '' });
  const [vtReportUrl, setVtReportUrl] = useState(null);
  const abortRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    abortRef.current = controller;

    async function load() {
      try {
        setLoading(true);
        setError(null);

        let tabUrl = '';
        let tabTitle = '';

        if (typeof chrome !== 'undefined' && chrome.tabs) {
          try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab) {
              tabUrl = tab.url || '';
              tabTitle = tab.title || '';
            }
          } catch (e) {
            // Chrome API not available during dev
          }
        }

        const url = tabUrl || 'https://example.com';
        const title = tabTitle || '';

        setTabInfo({ title, url });

        const vtUrl = await computeVtUrl(url);
        if (!cancelled) setVtReportUrl(vtUrl);

        const response = await fetch(`${BACKEND_URL}/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
          signal: controller.signal,
        });

        if (!response.ok) {
          const text = await response.text().catch(() => '');
          throw new Error(`Analysis failed (${response.status}): ${text}`);
        }

        const result = await response.json();
        if (cancelled) return;
        setData(result);

        if (result && result.s === 1 && result.id) {
          const deepResult = await pollDeepScan(result.id, controller.signal);
          if (!cancelled && deepResult) setData(deepResult);
        }
      } catch (err) {
        if (!cancelled && err.name !== 'AbortError') {
          setError(err.message || 'Failed to load analysis');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, []);

  return { data, loading, error, tabInfo, vtReportUrl };
}

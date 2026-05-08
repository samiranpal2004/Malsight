import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Loader2 } from 'lucide-react';
import api from '../api';
import VerdictBadge from '../components/VerdictBadge';
import MitreTag from '../components/MitreTag';
import ReasoningChain from '../components/ReasoningChain';

const SEVERITY_STYLES = {
  low:      'bg-green-900/40 border-green-700 text-green-300',
  medium:   'bg-yellow-900/40 border-yellow-700 text-yellow-300',
  high:     'bg-orange-900/40 border-orange-700 text-orange-300',
  critical: 'bg-red-900/40 border-red-700 text-red-300',
};

const ACTION_PALETTE = [
  { key: 'quarantine',              style: 'bg-red-900/40 border-red-700 text-red-200' },
  { key: 'monitor',                 style: 'bg-yellow-900/40 border-yellow-700 text-yellow-200' },
  { key: 'safe',                    style: 'bg-green-900/40 border-green-700 text-green-200' },
  { key: 'further analysis needed', style: 'bg-gray-800 border-gray-600 text-gray-200' },
];

function actionStyle(action = '') {
  const lower = action.toLowerCase();
  const match = ACTION_PALETTE.find(({ key }) => lower.includes(key));
  return match?.style ?? 'bg-gray-800 border-gray-600 text-gray-200';
}

function IOCSection({ label, items }) {
  if (!items?.length) return null;
  return (
    <div>
      <h3 className="text-xs text-gray-500 uppercase tracking-wider mb-2">{label}</h3>
      <div className="flex flex-wrap gap-2">
        {items.map((ioc, i) => (
          <span
            key={i}
            className="font-mono text-xs bg-gray-900 border border-gray-700 text-gray-300 px-2.5 py-1 rounded"
          >
            {ioc}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function Report() {
  const { job_id } = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api
      .get(`/report/${job_id}`)
      .then(({ data }) => {
        if (data.status === 'complete' && data.report) {
          setReport(data.report);
        } else if (data.status === 'failed') {
          setError(data.error || 'Analysis failed.');
        } else {
          setError('Report is not yet complete. Please wait and refresh.');
        }
      })
      .catch((err) => {
        setError(err.response?.data?.detail || err.message || 'Failed to load report.');
      })
      .finally(() => setLoading(false));
  }, [job_id]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96 gap-3 text-gray-400">
        <Loader2 className="w-5 h-5 animate-spin" />
        Loading report…
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-6 py-12">
        <div className="bg-red-900/30 border border-red-700 text-red-300 rounded-xl p-6">
          {error}
        </div>
      </div>
    );
  }

  const {
    verdict,
    confidence,
    threat_category,
    severity,
    mode,
    tools_called,
    analysis_time_seconds,
    summary,
    key_indicators = [],
    mitre_techniques = [],
    iocs = {},
    recommended_action,
    reasoning_chain,
  } = report;

  const steps = reasoning_chain?.steps ?? [];
  const modeLabel = mode === 'deep_scan' ? 'Deep Scan' : 'Standard';

  // Group MITRE techniques by tactic
  const byTactic = mitre_techniques.reduce((acc, t) => {
    const tactic = t.tactic || 'Other';
    (acc[tactic] ??= []).push(t);
    return acc;
  }, {});

  const hasIocs =
    iocs.ips?.length ||
    iocs.urls?.length ||
    iocs.domains?.length ||
    iocs.mutexes?.length ||
    iocs.crypto_wallets?.length;

  return (
    <div className="max-w-4xl mx-auto px-6 py-12 space-y-8">
      {/* Back button */}
      <Link
        to="/"
        className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Upload
      </Link>

      {/* Header row — verdict, severity, mode, stats */}
      <div className="flex flex-wrap items-center gap-3">
        <VerdictBadge verdict={verdict} confidence={confidence} />

        {threat_category && (
          <span className="text-sm text-gray-300 bg-gray-800 border border-gray-700 px-3 py-1.5 rounded-lg">
            {threat_category}
          </span>
        )}

        {severity && (
          <span
            className={`text-sm px-3 py-1.5 rounded-lg border font-semibold ${SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.medium}`}
            data-testid="severity-chip"
          >
            {severity.charAt(0).toUpperCase() + severity.slice(1)}
          </span>
        )}

        <span className="text-xs bg-gray-800 border border-gray-700 text-gray-400 px-2.5 py-1.5 rounded-lg">
          {modeLabel}
        </span>

        <span className="text-xs text-gray-500">
          {tools_called} tool calls · {analysis_time_seconds}s
        </span>
      </div>

      {/* Summary */}
      {summary && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
            Summary
          </h2>
          <p className="text-gray-100 leading-relaxed">{summary}</p>
        </div>
      )}

      {/* Key Indicators */}
      {key_indicators.length > 0 && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">
            Key Indicators
          </h2>
          <ol className="space-y-2">
            {key_indicators.map((indicator, i) => (
              <li key={i} className="flex items-start gap-3 text-sm text-gray-300">
                <span className="text-indigo-400 font-semibold shrink-0 w-5">{i + 1}.</span>
                {indicator}
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* MITRE ATT&CK */}
      {mitre_techniques.length > 0 && (
        <div
          className="bg-gray-800 border border-gray-700 rounded-xl p-6"
          data-testid="mitre-section"
        >
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">
            MITRE ATT&CK Techniques
          </h2>
          <div className="space-y-5">
            {Object.entries(byTactic).map(([tactic, techniques]) => (
              <div key={tactic}>
                <h3 className="text-xs text-gray-500 mb-2">{tactic}</h3>
                <div className="flex flex-wrap gap-2">
                  {techniques.map((t) => (
                    <MitreTag key={t.id} id={t.id} name={t.name} tactic={t.tactic} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* IOC Block */}
      {hasIocs ? (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 space-y-5">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
            Indicators of Compromise
          </h2>
          <IOCSection label="IP Addresses" items={iocs.ips} />
          <IOCSection label="URLs" items={iocs.urls} />
          <IOCSection label="Domains" items={iocs.domains} />
          <IOCSection label="Mutexes" items={iocs.mutexes} />
          <IOCSection label="Cryptocurrency Wallets" items={iocs.crypto_wallets} />
        </div>
      ) : null}

      {/* Reasoning Chain — collapsed by default */}
      {steps.length > 0 && <ReasoningChain steps={steps} />}

      {/* Recommended Action banner */}
      {recommended_action && (
        <div
          className={`border rounded-xl p-5 text-center font-semibold ${actionStyle(recommended_action)}`}
          data-testid="action-banner"
        >
          Recommended Action: {recommended_action}
        </div>
      )}
    </div>
  );
}

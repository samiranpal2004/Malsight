import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, Loader2 } from 'lucide-react';
import { getAttachmentReport } from '../api';
import VerdictBadge from '../components/VerdictBadge';
import MitreTag from '../components/MitreTag';
import ReasoningChain from '../components/ReasoningChain';

export default function AttachmentReport() {
  const { attachment_id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchReport = useCallback(() => {
    getAttachmentReport(attachment_id)
      .then(({ data }) => setData(data))
      .catch((err) => setError(err.response?.data?.detail ?? err.message ?? 'Failed to load report'))
      .finally(() => setLoading(false));
  }, [attachment_id]);

  useEffect(() => { fetchReport(); }, [fetchReport]);

  // Auto-refresh every 3s while report is not yet available
  useEffect(() => {
    if (!data) return;
    if (data.report_json) return; // report is ready
    const timer = setTimeout(fetchReport, 3000);
    return () => clearTimeout(timer);
  }, [data, fetchReport]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96 gap-3 text-gray-400">
        <Loader2 className="w-5 h-5 animate-spin" /> Loading…
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-6 py-12">
        <div className="bg-red-900/30 border border-red-700 text-red-300 rounded-xl p-6">{error}</div>
      </div>
    );
  }

  // Report not yet ready — show scanning status with live monitor link
  if (data && !data.report_json) {
    return (
      <div className="max-w-4xl mx-auto px-6 py-10 space-y-6">
        <button onClick={() => navigate(-1)} className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back
        </button>
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
          <h1 className="text-lg font-semibold text-white mb-1">{data.filename}</h1>
          {data.sha256 && <p className="text-xs text-gray-500">{data.sha256}</p>}
        </div>
        <div className="bg-blue-900/20 border border-blue-700 rounded-xl p-6 flex items-center gap-4">
          <Loader2 className="w-6 h-6 animate-spin text-blue-400 shrink-0" />
          <div>
            <p className="text-blue-300 font-medium">Analysis in progress…</p>
            <p className="text-blue-400/70 text-sm mt-0.5">This page refreshes automatically every 3 seconds.</p>
          </div>
          {data.job_id && (
            <Link
              to={`/job/${data.job_id}`}
              className="ml-auto text-xs bg-blue-900/40 border border-blue-700 text-blue-300 hover:bg-blue-800/40 px-3 py-1.5 rounded-lg transition-colors shrink-0"
            >
              Live Monitor
            </Link>
          )}
        </div>
      </div>
    );
  }

  const report = data?.report_json ?? {};
  const steps = report.reasoning_chain?.steps ?? [];
  const mitre = report.mitre_techniques ?? [];
  const iocs = report.iocs ?? {};
  const byTactic = mitre.reduce((acc, t) => {
    (acc[t.tactic || 'Other'] ??= []).push(t);
    return acc;
  }, {});

  return (
    <div className="max-w-4xl mx-auto px-6 py-10 space-y-6">
      <button onClick={() => navigate(-1)} className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition-colors">
        <ArrowLeft className="w-4 h-4" /> Back
      </button>

      <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
        <h1 className="text-lg font-semibold text-white mb-1">{data.filename}</h1>
        <p className="text-xs text-gray-500">{data.sha256}</p>
      </div>

      {data.verdict && (
        <div className="flex flex-wrap items-center gap-3">
          <VerdictBadge verdict={data.verdict} confidence={data.confidence} />
          {data.threat_category && (
            <span className="text-sm bg-gray-800 border border-gray-700 text-gray-300 px-3 py-1.5 rounded-lg">{data.threat_category}</span>
          )}
          {data.severity && (
            <span className="text-sm bg-gray-800 border border-gray-700 text-gray-300 px-3 py-1.5 rounded-lg">{data.severity}</span>
          )}
        </div>
      )}

      {report.summary && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Summary</h2>
          <p className="text-gray-100 leading-relaxed">{report.summary}</p>
        </div>
      )}

      {mitre.length > 0 && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">MITRE ATT&CK</h2>
          {Object.entries(byTactic).map(([tactic, techniques]) => (
            <div key={tactic} className="mb-4">
              <h3 className="text-xs text-gray-500 mb-2">{tactic}</h3>
              <div className="flex flex-wrap gap-2">
                {techniques.map((t) => <MitreTag key={t.id} id={t.id} name={t.name} tactic={t.tactic} />)}
              </div>
            </div>
          ))}
        </div>
      )}

      {(iocs.ips?.length || iocs.domains?.length || iocs.urls?.length) ? (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 space-y-4">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">IOCs</h2>
          {[['IPs', iocs.ips], ['Domains', iocs.domains], ['URLs', iocs.urls]].map(([label, items]) =>
            items?.length ? (
              <div key={label}>
                <h3 className="text-xs text-gray-500 mb-2">{label}</h3>
                <div className="flex flex-wrap gap-2">
                  {items.map((ioc, i) => (
                    <span key={i} className="font-mono text-xs bg-gray-900 border border-gray-700 text-gray-300 px-2.5 py-1 rounded">{ioc}</span>
                  ))}
                </div>
              </div>
            ) : null
          )}
        </div>
      ) : null}

      {steps.length > 0 && <ReasoningChain steps={steps} />}
    </div>
  );
}

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api';
import VerdictBadge from '../components/VerdictBadge';

const PAGE_SIZE = 20;

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function LoadingSkeleton() {
  return (
    <div className="space-y-2" data-testid="loading-skeleton">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="h-14 bg-gray-800 rounded-lg animate-pulse" />
      ))}
    </div>
  );
}

export default function History() {
  const navigate = useNavigate();

  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [verdictFilter, setVerdictFilter] = useState('');
  const [modeFilter, setModeFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  useEffect(() => {
    setLoading(true);
    setError('');

    const params = { page, page_size: PAGE_SIZE };
    if (verdictFilter) params.verdict = verdictFilter;
    if (modeFilter) params.mode = modeFilter;

    api
      .get('/reports', { params })
      .then(({ data }) => {
        setItems(data.items ?? []);
        setTotal(data.total ?? 0);
      })
      .catch((err) => {
        setError(err.response?.data?.detail || err.message || 'Failed to load reports.');
      })
      .finally(() => setLoading(false));
  }, [page, verdictFilter, modeFilter]);

  const handleVerdictChange = (e) => {
    setVerdictFilter(e.target.value);
    setPage(1);
  };

  const handleModeChange = (e) => {
    setModeFilter(e.target.value);
    setPage(1);
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-12">
      <h1 className="text-2xl font-bold text-gray-100 mb-8">Report History</h1>

      {/* Filter bar */}
      <div className="flex gap-3 mb-6" data-testid="filter-bar">
        <select
          value={verdictFilter}
          onChange={handleVerdictChange}
          data-testid="verdict-filter"
          className="bg-gray-800 border border-gray-700 text-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Verdicts</option>
          <option value="benign">Benign</option>
          <option value="suspicious">Suspicious</option>
          <option value="malicious">Malicious</option>
        </select>

        <select
          value={modeFilter}
          onChange={handleModeChange}
          data-testid="mode-filter"
          className="bg-gray-800 border border-gray-700 text-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Modes</option>
          <option value="standard">Standard</option>
          <option value="deep_scan">Deep Scan</option>
        </select>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-900/30 border border-red-700 text-red-300 rounded-lg p-4 mb-6 text-sm">
          {error}
        </div>
      )}

      {/* Table area */}
      {loading ? (
        <LoadingSkeleton />
      ) : items.length === 0 ? (
        <div
          className="text-center py-24 text-gray-500"
          data-testid="empty-state"
        >
          No analyses yet. Upload a file to get started.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left" data-testid="history-table">
            <thead>
              <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-gray-700">
                <th className="pb-3 pr-6 font-medium">Filename</th>
                <th className="pb-3 pr-6 font-medium">Mode</th>
                <th className="pb-3 pr-6 font-medium">Verdict</th>
                <th className="pb-3 pr-6 font-medium">Threat Category</th>
                <th className="pb-3 pr-6 font-medium">Confidence</th>
                <th className="pb-3 pr-6 font-medium">Tool Calls</th>
                <th className="pb-3 pr-6 font-medium">Time (s)</th>
                <th className="pb-3 font-medium">Date</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr
                  key={item.job_id}
                  onClick={() => navigate(`/job/${item.job_id}/report`)}
                  data-testid="history-row"
                  className="border-b border-gray-800 hover:bg-gray-800/60 cursor-pointer transition-colors"
                >
                  <td className="py-3 pr-6 font-mono text-gray-300 max-w-xs truncate">
                    {item.filename ?? '—'}
                  </td>
                  <td className="py-3 pr-6 text-gray-400">
                    {item.mode === 'deep_scan' ? 'Deep Scan' : 'Standard'}
                  </td>
                  <td className="py-3 pr-6">
                    {item.verdict ? (
                      <VerdictBadge verdict={item.verdict} confidence={item.confidence} />
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="py-3 pr-6 text-gray-400">{item.threat_category ?? '—'}</td>
                  <td className="py-3 pr-6 text-gray-300">
                    {item.confidence != null ? `${item.confidence}%` : '—'}
                  </td>
                  <td className="py-3 pr-6 text-gray-400">{item.tools_called ?? '—'}</td>
                  <td className="py-3 pr-6 text-gray-400">{item.analysis_time_seconds ?? '—'}</td>
                  <td className="py-3 text-gray-500 whitespace-nowrap">
                    {formatDate(item.completed_at ?? item.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {!loading && totalPages > 1 && (
        <div className="flex items-center gap-4 mt-6 text-sm text-gray-400" data-testid="pagination">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Prev
          </button>
          <span>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

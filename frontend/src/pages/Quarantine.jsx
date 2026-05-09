import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, Loader2, RotateCcw } from 'lucide-react';
import { getQuarantine, releaseQuarantine } from '../api';

export default function Quarantine() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [releasing, setReleasing] = useState(null);

  const fetchQuarantine = async () => {
    setLoading(true);
    setError('');
    try {
      const { data } = await getQuarantine();
      setItems(data.items ?? []);
      setTotal(data.total ?? 0);
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message ?? 'Failed to load quarantine');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchQuarantine(); }, []);

  const handleRelease = async (emailId) => {
    if (!window.confirm('Release this email from quarantine? It will be delivered to the inbox.')) return;
    setReleasing(emailId);
    try {
      await releaseQuarantine(emailId);
      setItems((prev) => prev.filter((i) => i.email_id !== emailId));
      setTotal((t) => t - 1);
    } catch (err) {
      alert(err.response?.data?.detail ?? err.message ?? 'Release failed');
    } finally {
      setReleasing(null);
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-10 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-red-400" />
          Quarantine Dashboard
        </h1>
        <span className="text-sm text-gray-500">{total} email{total !== 1 ? 's' : ''} quarantined</span>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-700 text-red-300 rounded-lg p-4 text-sm">{error}</div>
      )}

      {loading ? (
        <div className="flex items-center gap-2 text-gray-400 text-sm py-4">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading…
        </div>
      ) : items.length === 0 ? (
        <div className="text-center text-gray-500 py-16">
          <ShieldAlert className="w-12 h-12 mx-auto mb-3 opacity-20" />
          No quarantined emails
        </div>
      ) : (
        <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-xs text-gray-400 uppercase tracking-wider">
                <th className="text-left px-4 py-3">Sender</th>
                <th className="text-left px-4 py-3">Subject</th>
                <th className="text-left px-4 py-3">File</th>
                <th className="text-left px-4 py-3">Verdict</th>
                <th className="text-left px-4 py-3">Reason</th>
                <th className="text-left px-4 py-3">Time</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.quarantine_id} className="border-b border-gray-700/50 last:border-0 hover:bg-gray-700/30 transition-colors">
                  <td className="px-4 py-3 text-gray-300 max-w-[140px] truncate">
                    {item.sender_display || item.mail_from}
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/mail/email/${item.email_id}`}
                      className="text-indigo-400 hover:text-indigo-300 transition-colors truncate block max-w-[160px]"
                    >
                      {item.subject || '(no subject)'}
                    </Link>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-400 max-w-[120px] truncate">
                    {item.filename ?? '—'}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs bg-red-900/40 border border-red-700 text-red-300 px-2 py-0.5 rounded font-semibold">
                      {item.verdict?.toUpperCase() ?? 'MALICIOUS'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500 max-w-[180px] truncate">
                    {item.reason ?? '—'}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
                    {item.quarantined_at ? new Date(item.quarantined_at).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleRelease(item.email_id)}
                      disabled={releasing === item.email_id}
                      className="inline-flex items-center gap-1 text-xs bg-gray-700 hover:bg-gray-600 border border-gray-600 text-gray-300 px-2.5 py-1 rounded-lg transition-colors disabled:opacity-50"
                    >
                      {releasing === item.email_id
                        ? <Loader2 className="w-3 h-3 animate-spin" />
                        : <RotateCcw className="w-3 h-3" />}
                      Release
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

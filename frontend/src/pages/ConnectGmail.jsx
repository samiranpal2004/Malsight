import { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { Mail, CheckCircle, XCircle, Loader2, Trash2, Shield } from 'lucide-react';
import { listGmailAccounts, disconnectGmailAccount } from '../api';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export default function ConnectGmail() {
  const [searchParams]   = useSearchParams();
  const connected        = searchParams.get('connected');
  const error            = searchParams.get('error');

  const [accounts,      setAccounts]      = useState([]);
  const [loading,       setLoading]       = useState(true);
  const [disconnecting, setDisconnecting] = useState(null);

  const fetchAccounts = async () => {
    setLoading(true);
    try {
      const { data } = await listGmailAccounts();
      setAccounts(data.accounts ?? []);
    } catch {
      setAccounts([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAccounts(); }, []);

  const handleConnect = () => {
    window.location.href = `${API_BASE}/gmail/connect`;
  };

  const handleDisconnect = async (email) => {
    setDisconnecting(email);
    try {
      await disconnectGmailAccount(email);
      setAccounts((prev) => prev.filter((a) => a.email_address !== email));
    } catch {
      /* ignore */
    } finally {
      setDisconnecting(null);
    }
  };

  return (
    <div className="max-w-2xl mx-auto px-6 py-10 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Shield className="w-7 h-7 text-indigo-400" />
        <h1 className="text-2xl font-bold text-white">Gmail Integration</h1>
      </div>

      {/* Success banner */}
      {connected && (
        <div className="flex items-start gap-3 bg-green-900/30 border border-green-700 text-green-300 rounded-lg p-4 text-sm">
          <CheckCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold">{connected}</span> connected successfully.
            MalSight labels have been created in your Gmail account.
          </div>
        </div>
      )}

      {/* Error banner */}
      {error && (
        <div className="flex items-start gap-3 bg-red-900/30 border border-red-700 text-red-300 rounded-lg p-4 text-sm">
          <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
          Connection failed: <span className="font-mono">{error}</span>
        </div>
      )}

      {/* How it works */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 space-y-4">
        <h2 className="text-sm font-semibold text-gray-100 uppercase tracking-wide">
          How it works
        </h2>
        <ol className="text-sm text-gray-400 space-y-2 list-none">
          {[
            'Connect your Gmail account via Google OAuth.',
            'MalSight creates 5 labels in your Gmail: SCANNING, CLEAN, SUSPICIOUS, MALICIOUS, QUARANTINE.',
            'When a new email with a supported attachment arrives, MalSight scans it automatically.',
            'Scan results appear as Gmail labels within ~60 seconds.',
            'Malicious emails are moved out of Inbox into MALSIGHT_QUARANTINE.',
            'All verdicts are also visible in the MalSight Inbox view.',
          ].map((step, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-indigo-400 font-mono shrink-0">{i + 1}.</span>
              {step}
            </li>
          ))}
        </ol>

        <div className="pt-2 grid grid-cols-2 gap-2 text-xs text-gray-500">
          {['MALSIGHT_SCANNING', 'MALSIGHT_CLEAN', 'MALSIGHT_SUSPICIOUS', 'MALSIGHT_MALICIOUS', 'MALSIGHT_QUARANTINE'].map((lbl) => (
            <span
              key={lbl}
              className={`px-2 py-1 rounded font-mono ${
                lbl === 'MALSIGHT_CLEAN'       ? 'bg-green-900/40 text-green-300 border border-green-800' :
                lbl === 'MALSIGHT_SUSPICIOUS'  ? 'bg-yellow-900/40 text-yellow-300 border border-yellow-800' :
                lbl === 'MALSIGHT_MALICIOUS'   ? 'bg-red-900/40 text-red-400 border border-red-800' :
                lbl === 'MALSIGHT_QUARANTINE'  ? 'bg-red-950/60 text-red-300 border border-red-900' :
                'bg-blue-900/40 text-blue-300 border border-blue-800'
              }`}
            >
              {lbl}
            </span>
          ))}
        </div>

        <button
          onClick={handleConnect}
          className="w-full mt-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-5 py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
        >
          <Mail className="w-4 h-4" />
          Connect a Gmail Account
        </button>
      </div>

      {/* Connected accounts */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-gray-100 uppercase tracking-wide">
          Connected Accounts
        </h2>

        {loading ? (
          <div className="flex items-center gap-2 text-gray-400 text-sm py-2">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading…
          </div>
        ) : accounts.length === 0 ? (
          <p className="text-sm text-gray-500 py-2">No Gmail accounts connected yet.</p>
        ) : (
          accounts.map((account) => (
            <div
              key={account.email_address}
              className="flex items-center justify-between bg-gray-800 border border-gray-700 rounded-xl px-4 py-3"
            >
              <div className="space-y-0.5 min-w-0">
                <p className="text-sm font-medium text-gray-100 truncate">
                  {account.email_address}
                </p>
                <p className="text-xs text-gray-500">
                  Connected {new Date(account.connected_at).toLocaleDateString()}
                  {account.watching
                    ? ' · watching inbox'
                    : ' · poll mode (Pub/Sub not configured)'}
                  {account.watch_expiry &&
                    ` · watch expires ${new Date(account.watch_expiry).toLocaleDateString()}`}
                </p>
              </div>
              <button
                onClick={() => handleDisconnect(account.email_address)}
                disabled={disconnecting === account.email_address}
                title="Disconnect"
                className="ml-4 shrink-0 text-gray-500 hover:text-red-400 transition-colors p-2 rounded"
              >
                {disconnecting === account.email_address
                  ? <Loader2 className="w-4 h-4 animate-spin" />
                  : <Trash2 className="w-4 h-4" />}
              </button>
            </div>
          ))
        )}
      </div>

      <p className="text-xs text-gray-600">
        <Link to="/mail" className="hover:text-gray-400 underline transition-colors">
          ← Back to Inbox
        </Link>
      </p>
    </div>
  );
}

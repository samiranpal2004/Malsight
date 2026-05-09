import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Mail, RefreshCw, Loader2, Inbox as InboxIcon } from 'lucide-react';
import { getInbox } from '../api';

const STATUS_STYLES = {
  held:        'bg-blue-900/40 border-blue-700 text-blue-300',
  delivered:   'bg-green-900/40 border-green-700 text-green-300',
  warned:      'bg-yellow-900/40 border-yellow-700 text-yellow-300',
  quarantined: 'bg-red-900/40 border-red-700 text-red-300',
};

const VERDICT_CHIP = {
  benign:    'bg-green-900/40 border-green-700 text-green-300',
  suspicious:'bg-yellow-900/40 border-yellow-700 text-yellow-300',
  malicious: 'bg-red-900/40 border-red-700 text-red-300',
};

function AttachmentChip({ a }) {
  if (!a.verdict) {
    return (
      <span className="inline-flex items-center gap-1 text-xs bg-blue-900/30 border border-blue-700 text-blue-300 px-2 py-0.5 rounded">
        <Loader2 className="w-3 h-3 animate-spin" />
        {a.filename} — Scanning…
      </span>
    );
  }
  return (
    <span className={`inline-flex items-center gap-1 text-xs border px-2 py-0.5 rounded ${VERDICT_CHIP[a.verdict] ?? 'bg-gray-800 border-gray-600 text-gray-300'}`}>
      {a.filename} — {a.verdict.toUpperCase()}
    </span>
  );
}

export default function Inbox() {
  const [input, setInput] = useState('');
  const [recipient, setRecipient] = useState('');
  const [emails, setEmails] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const fetchEmails = useCallback(async (addr) => {
    if (!addr) return;
    setLoading(true);
    setError('');
    try {
      const { data } = await getInbox(addr);
      setEmails(data.items ?? []);
      setTotal(data.total ?? 0);
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message ?? 'Failed to load inbox');
    } finally {
      setLoading(false);
    }
  }, []);

  // Auto-refresh every 3s while any email is still being scanned
  useEffect(() => {
    if (!recipient) return;
    const hasHeld = emails.some((e) => e.delivery_status === 'held');
    if (!hasHeld) return;
    const timer = setTimeout(() => fetchEmails(recipient), 3000);
    return () => clearTimeout(timer);
  }, [emails, recipient, fetchEmails]);

  const handleSubmit = (e) => {
    e.preventDefault();
    const addr = input.trim();
    setRecipient(addr);
    fetchEmails(addr);
  };

  return (
    <div className="max-w-4xl mx-auto px-6 py-10 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <InboxIcon className="w-6 h-6 text-indigo-400" />
          Secure Inbox
        </h1>
        {recipient && (
          <button
            onClick={() => fetchEmails(recipient)}
            className="flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        )}
      </div>

      <form onSubmit={handleSubmit} className="flex gap-3">
        <input
          type="email"
          placeholder="recipient@company.com"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          className="flex-1 bg-gray-800 border border-gray-700 text-gray-100 rounded-lg px-4 py-2 text-sm placeholder-gray-500 focus:outline-none focus:border-indigo-500"
          required
        />
        <button
          type="submit"
          className="bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-5 py-2 rounded-lg transition-colors"
        >
          Load
        </button>
      </form>

      {error && (
        <div className="bg-red-900/30 border border-red-700 text-red-300 rounded-lg p-4 text-sm">
          {error}
        </div>
      )}

      {loading && (
        <div className="flex items-center gap-2 text-gray-400 text-sm py-4">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading…
        </div>
      )}

      {recipient && !loading && emails.length === 0 && !error && (
        <div className="text-center text-gray-500 py-16">
          <Mail className="w-10 h-10 mx-auto mb-3 opacity-30" />
          No emails for {recipient}
        </div>
      )}

      <div className="space-y-2">
        {emails.map((email) => (
          <Link
            key={email.email_id}
            to={`/mail/email/${email.email_id}`}
            className="block bg-gray-800 border border-gray-700 rounded-xl p-4 hover:border-indigo-700 transition-colors"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1 space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-medium text-gray-100 truncate">
                    {email.sender_display || email.mail_from}
                  </span>
                  <span className={`text-xs px-2 py-0.5 rounded border font-medium shrink-0 ${STATUS_STYLES[email.delivery_status] ?? 'bg-gray-800 border-gray-600 text-gray-400'}`}>
                    {email.delivery_status?.toUpperCase()}
                  </span>
                  {email.source === 'gmail' && (
                    <span className="text-xs px-2 py-0.5 rounded border font-medium shrink-0 bg-blue-950/50 border-blue-800 text-blue-400">
                      Gmail
                    </span>
                  )}
                </div>
                <p className="text-sm text-gray-400 truncate">
                  {email.subject || '(no subject)'}
                </p>
                {email.attachments?.length > 0 && (
                  <div className="flex flex-wrap gap-2 pt-1">
                    {email.attachments.map((a) => (
                      <AttachmentChip key={a.id} a={a} />
                    ))}
                  </div>
                )}
              </div>
              <time className="text-xs text-gray-500 shrink-0 pt-0.5">
                {email.received_at ? new Date(email.received_at).toLocaleString() : ''}
              </time>
            </div>
          </Link>
        ))}
      </div>

      {total > 0 && (
        <p className="text-xs text-gray-500 text-right">{total} email{total !== 1 ? 's' : ''}</p>
      )}
    </div>
  );
}

import { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Loader2, Paperclip, AlertTriangle, ShieldAlert, CheckCircle } from 'lucide-react';
import { getEmail } from '../api';

const VERDICT_STYLES = {
  benign:    { chip: 'bg-green-900/40 border-green-700 text-green-300', icon: CheckCircle },
  suspicious:{ chip: 'bg-yellow-900/40 border-yellow-700 text-yellow-300', icon: AlertTriangle },
  malicious: { chip: 'bg-red-900/40 border-red-700 text-red-300', icon: ShieldAlert },
};

const STATUS_BANNER = {
  quarantined: { style: 'bg-red-900/40 border-red-700 text-red-300', text: 'This email was quarantined — one or more attachments were identified as malicious.' },
  warned:      { style: 'bg-yellow-900/40 border-yellow-700 text-yellow-300', text: 'One or more attachments were flagged as suspicious. Review before opening.' },
};

function VerdictChip({ verdict, confidence }) {
  if (!verdict) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs bg-blue-900/30 border border-blue-700 text-blue-300 px-2.5 py-1 rounded-lg">
        <Loader2 className="w-3.5 h-3.5 animate-spin" />
        Scanning…
      </span>
    );
  }
  const { chip, icon: Icon } = VERDICT_STYLES[verdict] ?? { chip: 'bg-gray-800 border-gray-600 text-gray-300', icon: Loader2 };
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs border px-2.5 py-1 rounded-lg font-semibold ${chip}`}>
      <Icon className="w-3.5 h-3.5" />
      {verdict.toUpperCase()}
      {confidence != null && ` · ${confidence}%`}
    </span>
  );
}

export default function EmailDetail() {
  const { email_id } = useParams();
  const [email, setEmail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchEmail = useCallback(async () => {
    try {
      const { data } = await getEmail(email_id);
      setEmail(data);
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message ?? 'Failed to load email');
    } finally {
      setLoading(false);
    }
  }, [email_id]);

  useEffect(() => { fetchEmail(); }, [fetchEmail]);

  // Auto-refresh while any attachment is still scanning
  useEffect(() => {
    if (!email) return;
    const hasHeld = email.delivery_status === 'held' ||
      email.attachments?.some((a) => !a.verdict);
    if (!hasHeld) return;
    const timer = setTimeout(fetchEmail, 3000);
    return () => clearTimeout(timer);
  }, [email, fetchEmail]);

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

  const banner = STATUS_BANNER[email.delivery_status];

  return (
    <div className="max-w-4xl mx-auto px-6 py-10 space-y-6">
      <Link to="/mail" className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition-colors">
        <ArrowLeft className="w-4 h-4" /> Back to Inbox
      </Link>

      {/* Status banner */}
      {banner && (
        <div className={`border rounded-xl p-4 text-sm font-medium ${banner.style}`}>
          {banner.text}
        </div>
      )}

      {/* Email header */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 space-y-3">
        <h1 className="text-xl font-semibold text-white">{email.subject || '(no subject)'}</h1>
        <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <span className="text-gray-500">From</span>
          <span className="text-gray-200">{email.sender_display || email.mail_from}</span>
          <span className="text-gray-500">To</span>
          <span className="text-gray-200">{email.recipient_address}</span>
          {email.reply_to && (
            <>
              <span className="text-gray-500">Reply-To</span>
              <span className="text-gray-200">{email.reply_to}</span>
            </>
          )}
          <span className="text-gray-500">Date</span>
          <span className="text-gray-200">
            {email.received_at ? new Date(email.received_at).toLocaleString() : '—'}
          </span>
        </div>
      </div>

      {/* Attachments */}
      {email.attachments?.length > 0 && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 space-y-4">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
            <Paperclip className="w-3.5 h-3.5" />
            Attachments
          </h2>
          {email.attachments.map((a) => (
            <div key={a.id} className="flex items-center justify-between gap-4 py-3 border-b border-gray-700 last:border-0">
              <div className="space-y-1">
                <p className="text-sm font-medium text-gray-200">{a.filename}</p>
                {a.threat_category && (
                  <p className="text-xs text-gray-500">{a.threat_category}{a.severity ? ` · ${a.severity}` : ''}</p>
                )}
                {a.file_size_bytes && (
                  <p className="text-xs text-gray-600">{(a.file_size_bytes / 1024).toFixed(1)} KB</p>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <VerdictChip verdict={a.verdict} confidence={a.confidence} />
                {a.job_id && !a.verdict && (
                  <Link
                    to={`/job/${a.job_id}`}
                    className="text-xs bg-blue-900/40 border border-blue-700 text-blue-300 hover:bg-blue-800/40 px-2.5 py-1 rounded-lg transition-colors"
                  >
                    Monitor Analysis
                  </Link>
                )}
                {a.job_id && a.verdict && (
                  <Link
                    to={`/mail/attachment/${a.id}/report`}
                    className="text-xs bg-indigo-900/40 border border-indigo-700 text-indigo-300 hover:bg-indigo-800/40 px-2.5 py-1 rounded-lg transition-colors"
                  >
                    View Report
                  </Link>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Email body */}
      {(email.body_html || email.body_text) && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
          <div className="px-6 py-3 border-b border-gray-700">
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Message</span>
          </div>
          {email.body_html ? (
            <iframe
              srcDoc={email.body_html}
              sandbox="allow-same-origin"
              className="w-full min-h-64 bg-white"
              title="Email body"
            />
          ) : (
            <pre className="px-6 py-4 text-sm text-gray-300 whitespace-pre-wrap font-sans">
              {email.body_text}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

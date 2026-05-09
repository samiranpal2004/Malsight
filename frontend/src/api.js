import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
  headers: {
    'X-API-Key': import.meta.env.VITE_API_KEY || '',
  },
});

export const submitFile = (file, mode) => {
  const form = new FormData();
  form.append('file', file);
  form.append('mode', mode);
  return api.post('/analyze', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};

export const getReport = (jobId) => api.get(`/report/${jobId}`);

export const listReports = (page = 1, verdict = '', mode = '') =>
  api.get('/reports', { params: { page, page_size: 20, verdict, mode } });

export const getHealth = () => api.get('/health');

// ── Mail / Email Gateway ──────────────────────────────────────────────────────

export const getInbox = (recipient, page = 1, pageSize = 20) =>
  api.get('/mail/inbox', { params: { recipient, page, page_size: pageSize } });

export const getEmail = (emailId) => api.get(`/mail/email/${emailId}`);

export const getAttachmentReport = (attachmentId) =>
  api.get(`/mail/attachment/${attachmentId}/report`);

export const getQuarantine = (page = 1, pageSize = 20) =>
  api.get('/mail/quarantine', { params: { page, page_size: pageSize } });

export const releaseQuarantine = (emailId) =>
  api.post(`/mail/quarantine/${emailId}/release`);

export const getMailStats = () => api.get('/mail/stats');

// ── Gmail Integration ─────────────────────────────────────────────────────────

export const listGmailAccounts = () => api.get('/gmail/accounts');

export const disconnectGmailAccount = (email) =>
  api.delete(`/gmail/accounts/${encodeURIComponent(email)}`);

export const releaseGmailQuarantine = (gmailMessageId) =>
  api.post(`/gmail/release/${gmailMessageId}`);

export default api;

import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
  headers: {
    'X-API-Key': import.meta.env.VITE_API_KEY || 'dev-key',
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

export default api;

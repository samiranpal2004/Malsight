import { useState, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload as UploadIcon, FileCode, FileText, Archive, File, AlertCircle } from 'lucide-react';
import api from '../api';

const ALLOWED_EXTENSIONS = ['.exe', '.dll', '.py', '.sh', '.bash', '.pdf', '.zip'];
const MAX_SIZE_BYTES = 50 * 1024 * 1024;

const MODES = [
  {
    value: 'standard',
    icon: '⚡',
    label: 'Standard',
    desc: 'Fast triage. ~60 seconds.',
    detail: 'Recommended for most files.',
  },
  {
    value: 'deep_scan',
    icon: '🔬',
    label: 'Deep Scan',
    desc: 'Thorough investigation. Up to 5 minutes.',
    detail: 'For high-priority files.',
  },
];

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function FileIcon({ filename }) {
  const ext = filename.split('.').pop().toLowerCase();
  if (['py', 'sh', 'bash'].includes(ext)) return <FileCode className="w-6 h-6 text-indigo-400" />;
  if (ext === 'pdf') return <FileText className="w-6 h-6 text-red-400" />;
  if (ext === 'zip') return <Archive className="w-6 h-6 text-yellow-400" />;
  return <File className="w-6 h-6 text-gray-400" />;
}

function validateFile(f) {
  const ext = '.' + f.name.split('.').pop().toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return `File type "${ext}" is not supported. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`;
  }
  if (f.size > MAX_SIZE_BYTES) {
    return `File is too large (${formatBytes(f.size)}). Maximum size is 50 MB.`;
  }
  return null;
}

export default function Upload() {
  const navigate = useNavigate();
  const fileInputRef = useRef(null);
  const dragCounter = useRef(0);

  const [file, setFile] = useState(null);
  const [mode, setMode] = useState('standard');
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleFile = (f) => {
    if (!f) return;
    const err = validateFile(f);
    if (err) {
      setError(err);
      setFile(null);
    } else {
      setError('');
      setFile(f);
    }
  };

  const onDragEnter = useCallback((e) => {
    e.preventDefault();
    dragCounter.current += 1;
    setIsDragging(true);
  }, []);

  const onDragLeave = useCallback((e) => {
    e.preventDefault();
    dragCounter.current -= 1;
    if (dragCounter.current === 0) setIsDragging(false);
  }, []);

  const onDragOver = (e) => e.preventDefault();

  const onDrop = useCallback((e) => {
    e.preventDefault();
    dragCounter.current = 0;
    setIsDragging(false);
    handleFile(e.dataTransfer.files[0]);
  }, []);

  const onInputChange = (e) => handleFile(e.target.files[0]);

  const onSubmit = async () => {
    if (!file || loading) return;
    setLoading(true);
    setError('');

    const form = new FormData();
    form.append('file', file);
    form.append('mode', mode);

    try {
      const { data } = await api.post('/analyze', form);
      navigate(`/job/${data.job_id}`, {
        state: { filename: file.name, mode: data.mode },
      });
    } catch (err) {
      const detail = err.response?.data?.detail;
      const msg = typeof detail === 'string'
        ? detail
        : Array.isArray(detail)
          ? detail.map((d) => d.msg).join(', ')
          : err.message || 'Upload failed. Please try again.';
      setError(msg);
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-[calc(100vh-65px)] px-6 py-12">
      <div className="w-full max-w-2xl space-y-6">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-100">Analyze a File</h1>
          <p className="text-gray-400 mt-2">
            Upload a suspicious file. The AI agent will investigate and deliver a threat report.
          </p>
        </div>

        {/* Drop zone */}
        <div
          onDragEnter={onDragEnter}
          onDragLeave={onDragLeave}
          onDragOver={onDragOver}
          onDrop={onDrop}
          onClick={() => fileInputRef.current?.click()}
          data-testid="drop-zone"
          className={`border-2 border-dashed rounded-xl p-16 text-center cursor-pointer transition-all select-none ${
            isDragging
              ? 'border-indigo-400 bg-indigo-900/20'
              : 'border-gray-600 bg-gray-800/40 hover:border-gray-400 hover:bg-gray-800/60'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            accept={ALLOWED_EXTENSIONS.join(',')}
            onChange={onInputChange}
            data-testid="file-input"
          />

          {file ? (
            <div className="flex items-center justify-center gap-4 text-gray-100">
              <FileIcon filename={file.name} />
              <div className="text-left">
                <p className="font-semibold text-lg">{file.name}</p>
                <p className="text-sm text-gray-400 mt-0.5">{formatBytes(file.size)}</p>
              </div>
            </div>
          ) : (
            <div className="text-gray-400">
              <UploadIcon className="w-12 h-12 mx-auto mb-4 text-gray-500" />
              <p className="text-lg font-medium text-gray-300">Drop a file here</p>
              <p className="text-sm mt-1">or click to pick a file</p>
              <p className="text-xs mt-4 text-gray-600">
                {ALLOWED_EXTENSIONS.join(' · ')} &nbsp;·&nbsp; max 50 MB
              </p>
            </div>
          )}
        </div>

        {/* Mode selector */}
        <div className="grid grid-cols-2 gap-4">
          {MODES.map((m) => {
            const active = mode === m.value;
            return (
              <button
                key={m.value}
                onClick={() => setMode(m.value)}
                data-testid={`mode-${m.value}`}
                className={`p-5 rounded-xl border-2 text-left transition-all ${
                  active
                    ? 'border-indigo-500 bg-indigo-900/30'
                    : 'border-gray-700 bg-gray-800 hover:border-gray-500'
                }`}
              >
                <div className="text-2xl mb-2">{m.icon}</div>
                <p className={`font-semibold ${active ? 'text-indigo-300' : 'text-gray-200'}`}>
                  {m.label}
                </p>
                <p className={`text-sm mt-1 ${active ? 'text-indigo-400' : 'text-gray-400'}`}>
                  {m.desc}
                </p>
                <p className="text-xs mt-1 text-gray-500">{m.detail}</p>
              </button>
            );
          })}
        </div>

        {/* Inline error */}
        {error && (
          <div
            className="flex items-start gap-3 bg-red-900/30 border border-red-700 text-red-300 rounded-lg p-4 text-sm"
            data-testid="error-message"
          >
            <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
            {error}
          </div>
        )}

        {/* Submit */}
        <button
          onClick={onSubmit}
          disabled={!file || loading}
          data-testid="submit-button"
          className="w-full py-4 rounded-xl font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors text-lg"
        >
          {loading ? 'Uploading…' : 'Analyze File'}
        </button>
      </div>
    </div>
  );
}

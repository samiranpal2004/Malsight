import { useState, useRef } from 'react';
import { IconUpload, IconFolder, IconHash, IconArrowRight, IconFile, IconX, IconPlay } from '../icons/index.jsx';
import ScanModeToggle from '../shared/ScanModeToggle.jsx';
import DropZoneArt from '../shared/DropZoneArt.jsx';

export default function UploadZone({ onFile, onPasteHash, droppedFile, mode, setMode, onStart, loading, error }) {
  const [hover, setHover] = useState(false);
  const [drag, setDrag] = useState(false);
  const [hashOpen, setHashOpen] = useState(false);
  const [hashVal, setHashVal] = useState('');
  const inputRef = useRef(null);

  const onDrop = (e) => {
    e.preventDefault();
    setDrag(false);
    const f = e.dataTransfer.files?.[0];
    if (f) onFile(f);
  };

  if (droppedFile) {
    return (
      <div className="surface animate-fadeUp" style={{ padding: 24, borderRadius: 10 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 8, background: 'var(--bg-subtle)',
            border: '1px solid var(--border)', display: 'grid', placeItems: 'center',
            color: 'var(--amber-400)',
          }}>
            <IconFile size={20} />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div className="mono" style={{ fontSize: 14, fontWeight: 500 }}>{droppedFile.name}</div>
              <span className="hashpill">{droppedFile.detectedType}</span>
            </div>
            <div style={{ marginTop: 4, fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
              {droppedFile.sizeLabel} · queued for analysis
            </div>
          </div>
          <button className="btn btn-ghost" onClick={() => onFile(null)}>
            <IconX size={14} /> Remove
          </button>
        </div>
        <div className="divider" style={{ margin: '20px 0' }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <ScanModeToggle mode={mode} setMode={setMode} />
          <button 
            className="btn btn-primary focusable" 
            style={{ marginLeft: 'auto', opacity: loading ? 0.6 : 1 }} 
            onClick={onStart}
            disabled={loading}
          >
            <IconPlay size={13} /> {loading ? 'Uploading…' : 'Start analysis'}
          </button>
        </div>
        {error && (
          <div style={{ marginTop: 12, padding: 12, background: 'rgba(220, 38, 38, 0.1)', border: '1px solid rgba(220, 38, 38, 0.5)', borderRadius: 6, fontSize: 12, color: '#ff6b6b' }}>
            {error}
          </div>
        )}
      </div>
    );
  }

  // Show mode selector even before file drop
  const modeOptions = [
    { id: 'standard', label: 'Standard', icon: '⚡', desc: 'Fast triage ~60s' },
    { id: 'deep_scan', label: 'Deep Scan', icon: '🔬', desc: 'Thorough ~5min' },
  ];

  return (
    <div>
      <div
        className={`focusable${drag ? ' drop-active' : ''}${hover ? ' drop-hover' : ''}`}
        onDragEnter={(e) => { e.preventDefault(); setDrag(true); }}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={onDrop}
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
        onClick={() => inputRef.current?.click()}
        style={{
          position: 'relative',
          background: 'var(--bg-surface)',
          border: '1px dashed var(--border)',
          borderRadius: 10,
          padding: '38px 24px',
          minHeight: 240,
          display: 'grid', placeItems: 'center',
          textAlign: 'center',
          cursor: 'pointer',
          transition: 'background 150ms ease, border-color 150ms ease, box-shadow 150ms ease',
        }}
      >
        <DropZoneArt hover={hover || drag} />

        <input
          type="file"
          ref={inputRef}
          style={{ display: 'none' }}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) onFile(f);
          }}
        />

        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{
            width: 56, height: 56, margin: '0 auto 16px',
            display: 'grid', placeItems: 'center',
            color: hover || drag ? 'var(--amber-400)' : 'var(--text-secondary)',
            transition: 'color 150ms ease',
          }}>
            <IconUpload size={36} stroke={1.25} />
          </div>
          <div style={{ fontSize: 18, fontWeight: 600, letterSpacing: '-0.01em' }}>Drop any file to scan</div>
          <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginTop: 6 }}>
            EXE · DLL · PDF · ZIP · Scripts — up to 100MB
          </div>
          <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 18 }}>
            <button className="btn btn-primary" onClick={(e) => { e.stopPropagation(); inputRef.current?.click(); }}>
              <IconFolder size={13} /> Browse files
            </button>
            <button className="btn" onClick={(e) => { e.stopPropagation(); setHashOpen((v) => !v); }}>
              <IconHash size={13} /> Paste hash
            </button>
          </div>
        </div>
      </div>

      {/* Scan mode selector */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12, marginTop: 16 }}>
        {modeOptions.map((opt) => {
          const active = mode === opt.id;
          return (
            <button
              key={opt.id}
              onClick={() => setMode(opt.id)}
              className="focusable"
              style={{
                padding: '14px 16px',
                borderRadius: 8,
                background: active ? 'var(--bg-raised)' : 'var(--bg-subtle)',
                border: `1.5px solid ${active ? 'var(--amber-400)' : 'var(--border)'}`,
                color: active ? 'var(--amber-400)' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontFamily: 'inherit',
                fontSize: 13,
                fontWeight: 500,
                transition: 'all 150ms ease',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-start',
                gap: 4,
              }}
            >
              <span style={{ fontSize: 18, marginBottom: 4 }}>{opt.icon}</span>
              <span style={{ fontSize: 13, fontWeight: 600, color: active ? 'var(--amber-400)' : 'var(--text-primary)' }}>
                {opt.label}
              </span>
              <span style={{ fontSize: 11, color: active ? 'var(--amber-400)' : 'var(--text-muted)' }}>
                {opt.desc}
              </span>
            </button>
          );
        })}
      </div>

      {hashOpen && (
        <div className="surface animate-fadeUp" style={{ marginTop: 12, padding: 14, borderRadius: 8 }}>
          <div className="eyebrow" style={{ marginBottom: 8 }}>SHA-256 Lookup</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              className="input mono"
              placeholder="paste or type hash here…"
              value={hashVal}
              onChange={(e) => setHashVal(e.target.value)}
              autoFocus
            />
            <button className="btn btn-primary" onClick={() => { onPasteHash(hashVal); setHashOpen(false); }}>
              <IconArrowRight size={13} />
            </button>
          </div>
          <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
            Cross-references MalwareBazaar · VirusTotal · internal corpus (3.2M samples)
          </div>
        </div>
      )}
    </div>
  );
}

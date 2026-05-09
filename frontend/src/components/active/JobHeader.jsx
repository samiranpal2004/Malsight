import { IconFile, IconX } from '../icons/index.jsx';

export default function JobHeader({ job, progress, etaSec }) {
  return (
    <div className="surface" style={{ padding: 22, borderRadius: 10 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 8,
          background: 'var(--bg-subtle)', border: '1px solid var(--border)',
          display: 'grid', placeItems: 'center', color: 'var(--amber-400)',
        }}>
          <IconFile size={22} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div className="mono trunc" style={{ fontSize: 15, fontWeight: 500 }}>{job.filename}</div>
            <span className="hashpill" style={{ textTransform: 'uppercase', color: 'var(--amber-300)' }}>
              {job.mode === 'deep' ? 'Deep Scan' : 'Standard Scan'}
            </span>
          </div>
          <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 14, fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
            <span>{job.size}</span>
            <span>·</span>
            <span>{job.type}</span>
            <span>·</span>
            <span>SHA-256: <span style={{ color: 'var(--text-primary)' }}>{job.sha256.slice(0, 8)}…{job.sha256.slice(-4)}</span></span>
          </div>
        </div>
        <button className="btn btn-ghost" title="Cancel job">
          <IconX size={13} /> Abort
        </button>
      </div>

      <div style={{ marginTop: 18 }}>
        <div style={{ position: 'relative', height: 2, background: 'var(--bg-subtle)', borderRadius: 2, overflow: 'hidden' }}>
          <div style={{
            position: 'absolute', left: 0, top: 0, bottom: 0,
            width: `${progress}%`, background: 'var(--amber-400)',
            transition: 'width 300ms ease-out',
          }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8, fontSize: 11.5, color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
          <span><span style={{ color: 'var(--amber-300)' }}>{progress}%</span> · pipeline running</span>
          <span>~{etaSec}s remaining</span>
        </div>
      </div>
    </div>
  );
}

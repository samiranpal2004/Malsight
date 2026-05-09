const opts = [
  { id: 'standard', label: 'Standard Scan', sub: '< 60s · 8 tools' },
  { id: 'deep',     label: 'Deep Scan',     sub: '< 5m · 20 tools · memory' },
];

export default function ScanModeToggle({ mode, setMode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
      <div style={{
        display: 'inline-flex',
        background: 'var(--bg-subtle)',
        border: '1px solid var(--border)',
        borderRadius: 8,
        padding: 4, gap: 2,
      }}>
        {opts.map((o) => {
          const active = mode === o.id;
          return (
            <button
              key={o.id}
              onClick={() => setMode(o.id)}
              className="focusable"
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '7px 14px',
                background: active ? 'var(--bg-raised)' : 'transparent',
                border: 'none',
                borderRadius: 5,
                cursor: 'pointer',
                fontFamily: 'inherit',
                color: active ? 'var(--amber-400)' : 'var(--text-secondary)',
                fontSize: 13, fontWeight: active ? 500 : 400,
                transition: 'background 100ms ease, color 100ms ease',
              }}
            >
              <span style={{ width: 10, height: 10, borderRadius: '50%', border: '1.5px solid currentColor', position: 'relative' }}>
                {active && <span style={{ position: 'absolute', inset: 2, borderRadius: '50%', background: 'currentColor' }} />}
              </span>
              {o.label}
            </button>
          );
        })}
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
        {opts.find((o) => o.id === mode).sub}
      </div>
    </div>
  );
}

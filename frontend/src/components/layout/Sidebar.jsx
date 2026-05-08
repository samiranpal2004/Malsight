import { IconUpload, IconActivity, IconList, IconShield } from '../icons/index.jsx';

const navItems = [
  { id: 'upload',  label: 'Upload',       icon: IconUpload },
  { id: 'active',  label: 'Active',       icon: IconActivity },
  { id: 'reports', label: 'Reports',      icon: IconList },
  { id: 'intel',   label: 'Threat Intel', icon: IconShield },
];

export default function Sidebar({ route, setRoute, recent, jobState }) {
  return (
    <aside style={{
      width: 220, background: 'var(--bg-surface)', borderRight: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column', height: '100vh', flexShrink: 0,
    }}>
      {/* Brand */}
      <div style={{ padding: '18px 18px 16px', display: 'flex', alignItems: 'center', gap: 10 }}>
        <div className="hex-logo" />
        <div style={{ fontSize: 14, fontWeight: 600, letterSpacing: '-0.01em' }}>MalSight</div>
        <div style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>v2.4</div>
      </div>

      <div className="divider" style={{ marginBottom: 8 }} />

      {/* Nav */}
      <nav style={{ padding: '6px 10px' }}>
        {navItems.map((item) => {
          const active = route === item.id;
          const Icon = item.icon;
          const badge = item.id === 'active' && jobState === 'scanning' ? 1 : 0;
          return (
            <button
              key={item.id}
              onClick={() => setRoute(item.id)}
              className="focusable"
              style={{
                display: 'flex', alignItems: 'center', gap: 10,
                width: '100%',
                padding: '8px 10px',
                margin: '1px 0',
                background: 'transparent',
                border: 'none',
                borderLeft: active ? '2px solid var(--amber-400)' : '2px solid transparent',
                color: active ? 'var(--text-amber)' : 'var(--text-secondary)',
                fontSize: 13, fontWeight: active ? 500 : 400,
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'color 100ms ease',
                fontFamily: 'inherit',
              }}
              onMouseEnter={(e) => { if (!active) e.currentTarget.style.color = 'var(--text-primary)'; }}
              onMouseLeave={(e) => { if (!active) e.currentTarget.style.color = 'var(--text-secondary)'; }}
            >
              <Icon size={15} stroke={1.6} />
              <span>{item.label}</span>
              {badge ? (
                <span style={{
                  marginLeft: 'auto',
                  background: 'var(--bg-subtle)',
                  color: 'var(--text-secondary)',
                  fontSize: 10.5, padding: '1px 6px', borderRadius: 4,
                  fontFamily: 'JetBrains Mono, monospace',
                }}>{badge}</span>
              ) : null}
            </button>
          );
        })}
      </nav>

      <div className="divider" style={{ margin: '12px 18px' }} />

      {/* Recent scans */}
      <div style={{ padding: '0 18px' }}>
        <div className="eyebrow" style={{ marginBottom: 10 }}>Recent</div>
      </div>
      <div style={{ padding: '0 10px', overflow: 'auto', flex: 1 }}>
        {recent.map((r, i) => (
          <div
            key={i}
            className="row"
            style={{ padding: '8px 10px', borderRadius: 4, marginBottom: 1, cursor: 'pointer', fontSize: 12.5 }}
          >
            <div className="trunc" style={{ color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}>{r.name}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 3 }}>
              <span className={`dot dot-${r.verdict}`} />
              <span style={{ fontSize: 10.5, color: 'var(--text-secondary)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                {r.verdict === 'unknown' ? 'Scanning' : r.verdict}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div style={{ padding: '12px 18px', borderTop: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5, color: 'var(--text-secondary)' }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--verdict-clean)' }} />
          <span>All systems operational</span>
        </div>
        <div style={{ marginTop: 4, fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
          sandbox · us-east-1
        </div>
      </div>
    </aside>
  );
}

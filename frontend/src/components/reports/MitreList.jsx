import { IconShield } from '../icons/index.jsx';

export default function MitreList({ mitre }) {
  return (
    <div className="surface" style={{ borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: '12px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <IconShield size={14} />
        <span className="eyebrow">MITRE ATT&CK techniques</span>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>{mitre.length} techniques</span>
      </div>
      <div>
        {mitre.map((m, i) => (
          <div
            key={i}
            className="row animate-stepIn"
            style={{
              display: 'grid', gridTemplateColumns: '70px 1fr auto',
              alignItems: 'center', gap: 14,
              padding: '13px 18px',
              borderBottom: i < mitre.length - 1 ? '1px solid var(--border)' : 'none',
              animationDelay: `${i * 60 + 200}ms`,
            }}
          >
            <span className="mono" style={{ fontSize: 12.5, color: 'var(--amber-300)', fontWeight: 500 }}>{m.id}</span>
            <span style={{ fontSize: 13, color: 'var(--text-primary)' }}>{m.name}</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>{m.tactic}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

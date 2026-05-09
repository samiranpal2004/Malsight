import { IconAlert, IconNetwork, IconExternal, IconKey, IconFile } from '../icons/index.jsx';

export default function IOCTable({ iocs }) {
  return (
    <div className="surface" style={{ borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: '12px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
        <IconAlert size={14} />
        <span className="eyebrow">Indicators of compromise</span>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>{iocs.length} indicators</span>
      </div>
      <div>
        {iocs.map((ioc, i) => (
          <div
            key={i}
            className="row animate-stepIn"
            style={{
              display: 'grid', gridTemplateColumns: '90px 1fr auto',
              alignItems: 'center', gap: 12,
              padding: '14px 18px',
              borderBottom: i < iocs.length - 1 ? '1px solid var(--border)' : 'none',
              animationDelay: `${i * 60}ms`,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {ioc.type === 'IP'       && <IconNetwork  size={13} />}
              {ioc.type === 'Domain'   && <IconExternal size={13} />}
              {ioc.type === 'Registry' && <IconKey      size={13} />}
              {ioc.type === 'File'     && <IconFile     size={13} />}
              <span style={{ fontSize: 11, color: 'var(--text-secondary)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>{ioc.type}</span>
            </div>
            <div className="mono trunc" style={{ fontSize: 12.5, color: 'var(--text-primary)' }}>{ioc.value}</div>
            <span className="iocpill malicious">
              <span className="dot dot-malicious" style={{ width: 5, height: 5, boxShadow: 'none' }} />
              {ioc.source}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

import { IconFile } from '../icons/index.jsx';
import VerdictTag from './VerdictTag.jsx';

export default function RecentScansTable({ rows, onOpen }) {
  return (
    <div className="surface" style={{ borderRadius: 8, overflow: 'hidden' }}>
      <div style={{
        display: 'grid', gridTemplateColumns: '2fr 0.6fr 1.1fr 1fr 0.7fr',
        padding: '12px 18px',
        fontSize: 10.5, color: 'var(--text-muted)', letterSpacing: '0.08em',
        textTransform: 'uppercase', borderBottom: '1px solid var(--border)',
        fontWeight: 600,
      }}>
        <div>File name</div>
        <div>Type</div>
        <div>Verdict</div>
        <div>Time</div>
        <div>Mode</div>
      </div>
      {rows.map((r, i) => (
        <div
          key={i}
          className="row focusable"
          onClick={() => onOpen(r)}
          tabIndex={0}
          style={{
            display: 'grid', gridTemplateColumns: '2fr 0.6fr 1.1fr 1fr 0.7fr',
            padding: '13px 18px',
            borderBottom: i < rows.length - 1 ? '1px solid var(--border)' : 'none',
            cursor: 'pointer',
            alignItems: 'center',
            transition: 'background 100ms ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <IconFile size={14} />
            <span className="mono trunc" style={{ fontSize: 12.5 }}>{r.name}</span>
          </div>
          <div className="mono" style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{r.kind}</div>
          <VerdictTag verdict={r.verdict} />
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{r.time}</div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{r.mode}</div>
        </div>
      ))}
    </div>
  );
}

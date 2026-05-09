import { IconBolt } from '../icons/index.jsx';

export default function ReasoningStep({ s, live, streamText }) {
  const text = live ? streamText : s.thought;
  const showRest = !live;

  return (
    <div className="animate-stepIn" style={{ position: 'relative', paddingLeft: 28, marginBottom: 22 }}>
      {/* dot */}
      <div style={{
        position: 'absolute', left: 6, top: 4,
        width: 12, height: 12, borderRadius: '50%',
        background: live ? 'var(--amber-400)' : 'var(--bg-raised)',
        border: '2px solid ' + (live ? 'var(--amber-400)' : 'var(--border-strong)'),
        boxShadow: live ? '0 0 0 4px rgba(251,191,36,0.15)' : 'none',
      }} />
      {/* rail */}
      <div style={{ position: 'absolute', left: 11, top: 18, bottom: -22, width: 1, background: 'var(--border)' }} />

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        <span className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)', letterSpacing: '0.06em' }}>
          STEP {String(s.step).padStart(2, '0')}
        </span>
        <span className="mono" style={{
          fontSize: 11, color: 'var(--text-muted)',
          background: 'var(--bg-subtle)', padding: '1px 6px', borderRadius: 3,
        }}>{s.time}</span>
        {live && (
          <span className="live-badge">
            <span className="pulse" />Streaming
          </span>
        )}
      </div>

      <div style={{ fontSize: 13.5, lineHeight: 1.65, color: 'var(--text-primary)' }}>
        {text}
        {live && <span className="caret" />}
      </div>

      {showRest && (
        <div className="result-indent" style={{ marginTop: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 10.5, color: 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>tool</span>
            {s.tool.split(',').map((t, i) => (
              <span key={i} className="toolpill">
                <IconBolt size={10} /> {t.trim()}
              </span>
            ))}
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
            <span style={{ fontSize: 10.5, color: 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', marginTop: 2 }}>out</span>
            <div className="mono" style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.65, flex: 1 }}>
              → {s.result}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

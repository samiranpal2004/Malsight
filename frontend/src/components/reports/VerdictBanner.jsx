export default function VerdictBanner({ job }) {
  return (
    <div className="verdict-banner-mal animate-stepIn" style={{ padding: 22, borderRadius: 10 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 18 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{
              width: 14, height: 14, borderRadius: '50%',
              background: 'var(--verdict-malicious)',
              boxShadow: '0 0 0 5px rgba(220,38,38,0.18)',
            }} />
            <span style={{ fontSize: 22, fontWeight: 700, color: 'var(--verdict-malicious)', letterSpacing: '0.02em' }}>
              MALICIOUS
            </span>
          </div>
          <div style={{ marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {['Trojan-Dropper', 'Process Injection', 'C2 Communication'].map((t, i) => (
              <span key={i} className="hashpill" style={{ color: 'var(--text-primary)' }}>{t}</span>
            ))}
          </div>
        </div>
        <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>Confidence</div>
          <div className="tnum" style={{ fontSize: 28, fontWeight: 700, marginTop: 2 }}>
            {job.confidence}<span style={{ fontSize: 16, color: 'var(--text-secondary)' }}>%</span>
          </div>
          <div style={{ width: 140, height: 3, background: 'var(--bg-subtle)', borderRadius: 2, marginTop: 6 }}>
            <div style={{ width: `${job.confidence}%`, height: '100%', background: 'var(--amber-400)', borderRadius: 2 }} />
          </div>
        </div>
      </div>
      <div className="divider" style={{ margin: '18px 0 14px' }} />
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24, fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
        <span>completed in <span style={{ color: 'var(--text-primary)' }}>{job.duration}</span></span>
        <span>·</span>
        <span><span style={{ color: 'var(--text-primary)' }}>{job.toolCalls}</span> tool calls</span>
        <span>·</span>
        <span>mode: <span style={{ color: 'var(--amber-300)' }}>deep</span></span>
        <span>·</span>
        <span>family: <span style={{ color: 'var(--text-primary)' }}>{job.family}</span></span>
      </div>
    </div>
  );
}

import { IconBolt } from '../icons/index.jsx';

export default function ToolStatusStrip({ activeTools, used, total }) {
  const dots = Array.from({ length: total }, (_, i) => {
    if (i < used - 1) return 'on';
    if (i === used - 1) return 'live';
    return '';
  });

  return (
    <div className="surface" style={{ padding: '14px 18px', borderRadius: 8, display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0, flex: 1 }}>
        <div className="signal"><span /><span /><span /><span /></div>
        <span className="eyebrow" style={{ marginRight: 4 }}>Running</span>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {activeTools.map((t, i) => (
            <span key={i} className="toolpill"><IconBolt size={10} />{t}</span>
          ))}
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, color: 'var(--text-secondary)' }}>
        <span className="dotstrip">
          {dots.map((d, i) => <i key={i} className={d} />)}
        </span>
        <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
          {used}/{total} tool calls
        </span>
      </div>
    </div>
  );
}

import { useEffect, useRef } from 'react';
import { IconTerminal } from '../icons/index.jsx';
import ReasoningStep from './ReasoningStep.jsx';

export default function ReasoningChain({ steps, completedCount, liveStreamText, isLive }) {
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [completedCount, liveStreamText]);

  return (
    <div className="surface" style={{ borderRadius: 10, overflow: 'hidden' }}>
      <div style={{
        padding: '12px 18px', borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', gap: 10,
      }}>
        <IconTerminal size={14} />
        <span className="eyebrow">Agent reasoning chain</span>
        {isLive && (
          <span className="live-badge" style={{ marginLeft: 'auto' }}>
            <span className="pulse" /> Live
          </span>
        )}
      </div>
      <div ref={scrollRef} className="reasoning-scroll" style={{
        maxHeight: 420, overflowY: 'auto',
        padding: '18px 22px', position: 'relative',
      }}>
        {steps.slice(0, completedCount).map((s) => (
          <ReasoningStep key={s.step} s={s} live={false} />
        ))}
        {isLive && completedCount < steps.length && (
          <ReasoningStep s={steps[completedCount]} live={true} streamText={liveStreamText} />
        )}
        {!isLive && completedCount >= steps.length && (
          <div style={{ padding: '8px 0 0 28px', fontSize: 12, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
            ── reasoning complete · 5 steps · 14 tool calls ──
          </div>
        )}
      </div>
    </div>
  );
}

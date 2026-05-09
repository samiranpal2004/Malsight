const glyphs = [
  { l: '0xA3', d: 0,   x: 0  },
  { l: 'PE32', d: 1.1, x: 32 },
  { l: '7c2',  d: 2.2, x: 68 },
  { l: 'ZIP',  d: 0.6, x: 96 },
  { l: 'a39',  d: 1.7, x: 14 },
  { l: '0xFB', d: 2.8, x: 50 },
];

export default function DropZoneArt({ hover }) {
  return (
    <>
      <svg
        width="120" height="138" viewBox="0 0 120 138"
        style={{ position: 'absolute', left: 24, top: '50%', transform: 'translateY(-50%)', opacity: 0.18, pointerEvents: 'none' }}
      >
        <path d="M60 4 l52 30 v68 l-52 30 -52-30 V34 z" stroke="var(--border-strong)" strokeWidth="1" fill="none" />
        <path d="M60 22 l36 21 v44 l-36 21 -36-21 V43 z" stroke="var(--border)" strokeWidth="1" fill="none" />
      </svg>
      <div style={{
        position: 'absolute', right: 28, top: 22, bottom: 22, width: 110,
        pointerEvents: 'none', opacity: 0.6,
        fontFamily: 'JetBrains Mono, monospace', fontSize: 10,
        color: hover ? 'var(--amber-300)' : 'var(--text-muted)',
        transition: 'color 200ms ease',
      }}>
        {glyphs.map((g, i) => (
          <span key={i} style={{ position: 'absolute', left: g.x, top: 0, animation: `dropletFall 3.2s linear ${g.d}s infinite` }}>
            {g.l}
          </span>
        ))}
      </div>
    </>
  );
}

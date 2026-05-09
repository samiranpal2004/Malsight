const verdictMap = {
  malicious:  { color: '#FCA5A5', label: 'MALICIOUS' },
  clean:      { color: '#86EFAC', label: 'CLEAN' },
  benign:     { color: '#86EFAC', label: 'BENIGN' },
  suspicious: { color: '#FCD34D', label: 'SUSPICIOUS' },
  unknown:    { color: 'var(--text-secondary)', label: 'SCANNING' },
};

export default function VerdictTag({ verdict }) {
  const v = verdictMap[verdict] || verdictMap.unknown;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7 }}>
      <span className={`dot dot-${verdict}`} />
      <span className="mono" style={{ fontSize: 11.5, letterSpacing: '0.06em', color: v.color, fontWeight: 500 }}>{v.label}</span>
    </span>
  );
}

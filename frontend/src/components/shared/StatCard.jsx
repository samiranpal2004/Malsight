export default function StatCard({ value, label, sub }) {
  return (
    <div className="surface" style={{ padding: '18px 20px', borderRadius: 8 }}>
      <div className="tnum" style={{ fontSize: 26, fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>{value}</div>
      <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>{label}</div>
      {sub && <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 6, fontFamily: 'JetBrains Mono, monospace' }}>{sub}</div>}
    </div>
  );
}

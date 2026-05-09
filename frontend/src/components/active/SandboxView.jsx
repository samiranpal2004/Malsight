import { IconBox } from '../icons/index.jsx';

export default function SandboxView({ active, used, capturedDump, blockedNet, schtasks }) {
  const events = [];
  if (used >= 2) events.push({ t: 'T+0.0s', ev: 'docker.exec()', tone: 'muted' });
  if (used >= 2) events.push({ t: 'T+0.8s', ev: 'payload decompressed', tone: 'amber' });
  if (used >= 2) events.push({ t: 'T+3.0s', ev: 'capture_memory_dump → 14MB', tone: 'amber' });
  if (used >= 2) events.push({ t: 'T+4.2s', ev: 'schtasks.exe spawned', tone: 'mal' });
  if (used >= 2) events.push({ t: 'T+5.7s', ev: 'http://185.220.101.45/gate.php BLOCKED', tone: 'mal' });
  if (used >= 3) events.push({ t: 'T+8.1s', ev: 'CreateRemoteThread → svchost32.exe', tone: 'mal' });
  if (used >= 4) events.push({ t: 'T+11.4s', ev: 'WinHttpOpen() → C2 ping', tone: 'mal' });

  return (
    <div className={`sandbox-frame${active ? '' : ' idle'}`} style={{ padding: 18 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <IconBox size={14} />
        <span className="eyebrow">Sandbox · isolated container</span>
        <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--text-secondary)' }}>
          <span style={{
            width: 6, height: 6, borderRadius: '50%',
            background: active ? 'var(--amber-400)' : 'var(--text-muted)',
            animation: active ? 'liveDot 1.4s ease-in-out infinite' : 'none',
          }} />
          <span className="mono">{active ? 'RUNNING' : 'IDLE'}</span>
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 0.9fr', gap: 16 }}>
        {/* Process tree */}
        <div className="ascii-grid" style={{ borderRadius: 6, padding: 14, minHeight: 180, position: 'relative', background: 'var(--bg-base)', border: '1px solid var(--border)' }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, lineHeight: 1.85 }}>
            <div style={{ color: 'var(--text-secondary)' }}>
              <span style={{ color: 'var(--amber-300)' }}>[root]</span> sandbox.docker
            </div>
            <div style={{ color: 'var(--text-secondary)', paddingLeft: 14 }}>
              ├── <span style={{ color: 'var(--text-primary)' }}>Adobe_CC_…crack.exe</span> <span style={{ color: 'var(--text-muted)' }}>(pid 1042)</span>
            </div>
            <div style={{ color: used >= 2 ? '#FCA5A5' : 'var(--text-muted)', paddingLeft: 32 }}>
              │   ├── schtasks.exe <span style={{ color: 'var(--text-muted)' }}>(persistence)</span>
            </div>
            <div style={{ color: used >= 3 ? '#FCA5A5' : 'var(--text-muted)', paddingLeft: 32 }}>
              │   └── svchost32.exe <span style={{ color: 'var(--text-muted)' }}>(injected · 0x3f2000)</span>
            </div>
            <div style={{ color: 'var(--text-secondary)', paddingLeft: 14 }}>
              └── <span style={{ color: 'var(--steel-300)' }}>monitor</span> <span style={{ color: 'var(--text-muted)' }}>(syscall trace)</span>
            </div>
          </div>
          <div style={{ position: 'absolute', bottom: 12, right: 14, fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
            mem · {capturedDump ? '14.0 MB captured' : '— pending —'}
          </div>
        </div>

        {/* Event log */}
        <div style={{ borderRadius: 6, background: 'var(--bg-base)', border: '1px solid var(--border)', padding: 14, fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5, minHeight: 180, overflow: 'hidden' }}>
          {events.length === 0 && (
            <div style={{ color: 'var(--text-muted)' }}>// awaiting sandbox detonation…</div>
          )}
          {events.map((e, i) => {
            const c = e.tone === 'mal' ? '#FCA5A5' : e.tone === 'amber' ? 'var(--amber-300)' : 'var(--text-secondary)';
            return (
              <div key={i} className="animate-fadeUp" style={{ display: 'flex', gap: 10, padding: '2px 0' }}>
                <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>{e.t}</span>
                <span style={{ color: c }}>{e.ev}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom metrics */}
      <div style={{ display: 'flex', gap: 22, marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--border)', fontSize: 11.5, color: 'var(--text-secondary)' }}>
        <span><span className="mono" style={{ color: 'var(--text-primary)' }}>{blockedNet}</span> blocked net calls</span>
        <span><span className="mono" style={{ color: 'var(--text-primary)' }}>{schtasks}</span> persistence ops</span>
        <span><span className="mono" style={{ color: 'var(--text-primary)' }}>{capturedDump ? '14.0 MB' : '0 KB'}</span> mem dumped</span>
        <span style={{ marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-muted)' }}>
          docker · alpine-3.19 · 512mb · no-net
        </span>
      </div>
    </div>
  );
}

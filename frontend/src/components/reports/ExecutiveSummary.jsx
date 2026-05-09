import { IconList, IconCopy, IconExternal, IconLock } from '../icons/index.jsx';

export default function ExecutiveSummary({ job }) {
  return (
    <div className="surface" style={{ borderRadius: 10, padding: 22 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
        <IconList size={14} />
        <span className="eyebrow">Executive summary</span>
      </div>
      <div style={{ fontSize: 14.5, lineHeight: 1.75, color: 'var(--text-primary)' }}>
        <span className="mono" style={{ color: 'var(--amber-300)' }}>{job.filename}</span> is a UPX-packed dropper that decompresses
        a secondary payload at runtime, injects code into <span className="mono" style={{ color: 'var(--text-primary)' }}>svchost32.exe</span>{' '}
        via <span className="mono" style={{ color: 'var(--text-primary)' }}>CreateRemoteThread</span>, and establishes a registry
        Run-key for persistence. The injected binary attempts outbound HTTP to a known C2 endpoint{' '}
        (<span className="mono" style={{ color: '#FCA5A5' }}>185.220.101.45</span>, AbuseIPDB 97/100). Network egress was blocked
        in sandbox; <span style={{ color: 'var(--text-primary)' }}>7 outbound calls</span> were observed. Recommended action:{' '}
        <span style={{ color: 'var(--amber-300)' }}>quarantine across all endpoints</span> and rotate any credentials accessed
        since first observation.
      </div>
      <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
        <button className="btn btn-primary"><IconCopy size={13} /> Copy STIX bundle</button>
        <button className="btn"><IconExternal size={13} /> Push to SIEM</button>
        <button className="btn"><IconLock size={13} /> Quarantine</button>
      </div>
    </div>
  );
}

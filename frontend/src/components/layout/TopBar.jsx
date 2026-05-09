import { IconSearch } from '../icons/index.jsx';

const titleMap = {
  upload:  'Workspace',
  active:  'Live Analysis',
  reports: 'Threat Report',
  intel:   'Threat Intelligence',
};

export default function TopBar({ route, currentJob }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 12,
      padding: '14px 28px',
      borderBottom: '1px solid var(--border)',
      background: 'var(--bg-base)',
      height: 56,
      flexShrink: 0,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--text-secondary)' }}>
        <span style={{ color: 'var(--text-muted)' }}>MalSight</span>
        <span style={{ color: 'var(--text-muted)' }}>/</span>
        <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{titleMap[route] || ''}</span>
        {route === 'active' && currentJob && (
          <>
            <span style={{ color: 'var(--text-muted)' }}>/</span>
            <span className="mono" style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{currentJob.name}</span>
          </>
        )}
      </div>
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
        <div className="hashpill">
          <span style={{ color: 'var(--text-muted)' }}>analyst</span> · jay.kim
        </div>
        <button className="btn btn-ghost" style={{ padding: '0 10px' }}>
          <IconSearch size={14} />
          <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Search</span>
          <span className="mono" style={{ fontSize: 10.5, padding: '1px 5px', background: 'var(--bg-subtle)', borderRadius: 3, color: 'var(--text-muted)', marginLeft: 4 }}>⌘K</span>
        </button>
      </div>
    </div>
  );
}

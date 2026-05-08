export default function MitreTag({ id, name, tactic }) {
  // MITRE sub-technique URLs use slashes: T1027.002 → /techniques/T1027/002
  const urlId = id.replace('.', '/');
  const href = `https://attack.mitre.org/techniques/${urlId}`;

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={tactic ? `Tactic: ${tactic}` : undefined}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-gray-700 hover:bg-gray-600 border border-gray-600 hover:border-gray-500 rounded text-xs font-mono text-gray-300 hover:text-white transition-colors"
      data-testid="mitre-tag"
    >
      <span className="text-indigo-400">{id}</span>
      <span className="text-gray-500">·</span>
      <span>{name}</span>
    </a>
  );
}

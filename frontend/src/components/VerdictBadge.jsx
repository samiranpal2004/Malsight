const STYLES = {
  benign:     'bg-green-900/40 border-green-700 text-green-300',
  suspicious: 'bg-yellow-900/40 border-yellow-700 text-yellow-300',
  malicious:  'bg-red-900/40 border-red-700 text-red-300',
};

const EMOJIS = {
  benign:     '🟢',
  suspicious: '🟡',
  malicious:  '🔴',
};

export default function VerdictBadge({ verdict, confidence }) {
  const style = STYLES[verdict] ?? STYLES.suspicious;
  const emoji = EMOJIS[verdict] ?? '⚪';
  const label = verdict ? verdict.charAt(0).toUpperCase() + verdict.slice(1) : 'Unknown';

  return (
    <span
      className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-semibold ${style}`}
      data-testid="verdict-badge"
    >
      {emoji} {label}
      {confidence != null && (
        <span className="text-xs font-normal opacity-75">· {confidence}%</span>
      )}
    </span>
  );
}

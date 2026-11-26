// Every verdict has a text label and an icon, never colour alone (FR-004, NFR-012).
const VERDICTS = {
  SAFE: { label: 'Safe', icon: '✓' },
  SUSPICIOUS: { label: 'Suspicious', icon: '!' },
  MALICIOUS: { label: 'Malicious', icon: '✕' },
};

export default function VerdictBadge({ verdict, large = false }) {
  if (!verdict) return <span className="muted">Not checked</span>;
  const v = VERDICTS[verdict];
  return (
    <span className={`verdict verdict-${verdict}${large ? ' verdict-large' : ''}`}>
      <span className="verdict-icon" aria-hidden="true">{v.icon}</span>
      {v.label}
    </span>
  );
}

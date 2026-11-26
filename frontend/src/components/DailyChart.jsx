import { useState } from 'react';

/**
 * Single-series bar chart of verifications per day (FR-045). One hue, no legend (the title names the
 * series), a tooltip on hover and keyboard focus, and the same numbers in a screen-reader table.
 */
export default function DailyChart({ title, days }) {
  const [active, setActive] = useState(null);
  const max = Math.max(1, ...days.map((d) => d.count));
  const total = days.reduce((sum, d) => sum + d.count, 0);
  const label = (d) => new Date(`${d.date}T00:00:00`).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

  return (
    <figure className="chart">
      <figcaption className="chart-title">{title} <span className="muted">· {total} total</span></figcaption>
      <div className="chart-plot" aria-hidden="true">
        <div className="chart-gridline" style={{ bottom: '100%' }}><span>{max}</span></div>
        <div className="chart-gridline" style={{ bottom: '0%' }}><span>0</span></div>
        <div className="chart-bars">
          {days.map((d, i) => (
            <div key={d.date} className="chart-slot" tabIndex={0}
              onMouseEnter={() => setActive(i)} onMouseLeave={() => setActive(null)}
              onFocus={() => setActive(i)} onBlur={() => setActive(null)}>
              <div className={`chart-bar${active === i ? ' is-active' : ''}`} style={{ height: `${(d.count / max) * 100}%` }} />
              {active === i && <div className="chart-tip">{label(d)}: <strong>{d.count}</strong> check{d.count === 1 ? '' : 's'}</div>}
            </div>
          ))}
        </div>
      </div>
      <div className="chart-axis" aria-hidden="true">
        <span>{label(days[0])}</span><span>{label(days[days.length - 1])}</span>
      </div>
      <table className="sr-only">
        <caption>{title}</caption>
        <thead><tr><th>Date</th><th>Verifications</th></tr></thead>
        <tbody>{days.map((d) => <tr key={d.date}><td>{label(d)}</td><td>{d.count}</td></tr>)}</tbody>
      </table>
    </figure>
  );
}

import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { CATEGORY_LABELS, formatDateTime } from '../format.js';

export default function PublicReportsPage() {
  const [query, setQuery] = useState('');
  const [submitted, setSubmitted] = useState('');
  const [category, setCategory] = useState('');
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams({ query: submitted });
    if (category) params.set('category', category);
    setError(null);
    api(`/api/reports/public?${params}`).then(setItems).catch((e) => setError(e.message));
  }, [submitted, category]);

  return (
    <section>
      <h2>Reported Scam Links</h2>
      <p className="muted">
        Links reported by PhishMeNot users and confirmed by an administrator. They are shown in a safe, non-clickable form
        (<code>hxxps://example[.]com</code>). <strong>Do not open these links.</strong>
      </p>

      <form className="search" onSubmit={(e) => { e.preventDefault(); setSubmitted(query.trim()); }}>
        <label htmlFor="category" className="sr-only">Filter by category</label>
        <select id="category" value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All categories</option>
          {Object.entries(CATEGORY_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        <input type="search" placeholder="Search by link text" value={query} onChange={(e) => setQuery(e.target.value)}
          maxLength={255} aria-label="Search reported links" />
        <button className="btn" type="submit">Search</button>
      </form>

      {error && <div className="alert alert-error" role="alert">{error}</div>}
      {!items && !error && <div className="muted">Loading…</div>}
      {items && items.length === 0 && <div className="card empty">No reported links match your search.</div>}
      {items && items.length > 0 && (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead><tr><th>Link (do not open)</th><th>Category</th><th>Reports</th><th>First reported</th></tr></thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.defangedUrl}>
                    <td className="url-cell"><code>{r.defangedUrl}</code></td>
                    <td>{CATEGORY_LABELS[r.category]}</td>
                    <td>{r.reportCount}</td>
                    <td>{formatDateTime(r.firstReportedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}

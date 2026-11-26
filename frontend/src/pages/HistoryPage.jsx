import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api.js';
import { useAuth } from '../auth/AuthContext.jsx';
import VerdictBadge from '../components/VerdictBadge.jsx';
import { formatDateTime } from '../format.js';

export default function HistoryPage() {
  const { sessionExpired } = useAuth();
  const [verdict, setVerdict] = useState('');
  const [query, setQuery] = useState('');
  const [submitted, setSubmitted] = useState('');
  const [page, setPage] = useState(0);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    const params = new URLSearchParams({ query: submitted, page: String(page), size: '10' });
    if (verdict) params.set('verdict', verdict);
    setError(null);
    api(`/api/verifications?${params}`)
      .then(setData)
      .catch((e) => (e.status === 401 ? sessionExpired() : setError(e.message)));
  }, [verdict, submitted, page, reload, sessionExpired]);

  async function remove(item) {
    if (!window.confirm(`Delete this entry from your history?\n\n${item.submittedUrl}`)) return;
    try {
      await api(`/api/verifications/${item.id}`, { method: 'DELETE' });
      if (data.items.length === 1 && page > 0) setPage(page - 1);
      else setReload((n) => n + 1);
    } catch (e) {
      if (e.status === 401) return sessionExpired();
      setError(e.message);
    }
  }

  return (
    <section>
      <h2>Verification History</h2>
      <p className="muted">Links you have checked, newest first.</p>

      <form className="search" onSubmit={(e) => { e.preventDefault(); setPage(0); setSubmitted(query.trim()); }}>
        <label htmlFor="verdict" className="sr-only">Filter by verdict</label>
        <select id="verdict" value={verdict} onChange={(e) => { setPage(0); setVerdict(e.target.value); }}>
          <option value="">All verdicts</option>
          <option value="SAFE">Safe</option>
          <option value="SUSPICIOUS">Suspicious</option>
          <option value="MALICIOUS">Malicious</option>
        </select>
        <input type="search" placeholder="Search by link" value={query} onChange={(e) => setQuery(e.target.value)}
          maxLength={255} aria-label="Search history by link" />
        <button className="btn" type="submit">Search</button>
      </form>

      {error && <div className="alert alert-error" role="alert">{error}</div>}
      {!data && !error && <div className="muted">Loading history…</div>}
      {data && data.totalElements === 0 && (
        <div className="card empty">
          {submitted || verdict ? 'No checks match your filters.' : <>You have not checked any links yet. <Link to="/check">Check a link</Link></>}
        </div>
      )}
      {data && data.totalElements > 0 && (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead><tr><th>Link</th><th>Verdict</th><th>Checked on</th><th><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {data.items.map((item) => (
                  <tr key={item.id}>
                    <td className="url-cell"><code>{item.submittedUrl}</code></td>
                    <td><VerdictBadge verdict={item.verdict} /></td>
                    <td>{formatDateTime(item.createdAt)}</td>
                    <td><button className="btn btn-outline btn-small" onClick={() => remove(item)}>Delete</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pager">
            <button className="btn btn-outline" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
            <span className="muted">Page {data.page + 1} of {data.totalPages} · {data.totalElements} check(s)</span>
            <button className="btn btn-outline" disabled={data.page + 1 >= data.totalPages} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        </div>
      )}
    </section>
  );
}

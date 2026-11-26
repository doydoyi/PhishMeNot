import { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { useAuth } from '../auth/AuthContext.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import VerdictBadge from '../components/VerdictBadge.jsx';
import { CATEGORY_LABELS, STATUS_LABELS, formatDateTime } from '../format.js';

const TABS = ['PENDING', 'APPROVED', 'REJECTED', 'REMOVED'];

export default function AdminReportsPage() {
  const { sessionExpired } = useAuth();
  const [status, setStatus] = useState('PENDING');
  const [items, setItems] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(null);

  const load = useCallback(() => {
    api(`/api/admin/reports?status=${status}`)
      .then(setItems)
      .catch((e) => (e.status === 401 ? sessionExpired() : setMessage({ type: 'error', text: e.message })));
  }, [status, sessionExpired]);
  useEffect(() => { setItems(null); load(); }, [load]);

  async function act(report, action) {
    setBusy(report.id);
    setMessage(null);
    try {
      if (action === 'RECHECK') {
        const r = await api(`/api/admin/reports/${report.id}/recheck`, { method: 'POST' });
        setMessage({ type: 'info', text: `Re-checked ${report.url}: ${r.verdict.toLowerCase()}. ${r.explanation}` });
      } else {
        await api(`/api/admin/reports/${report.id}`, { method: 'PATCH', body: { action } });
        const done = { APPROVE: 'approved and added to the public list', REJECT: 'rejected', REMOVE: 'removed from the public list' }[action];
        setMessage({ type: 'success', text: `Report ${done}.` });
      }
      load();
    } catch (e) {
      if (e.status === 401) return sessionExpired();
      setMessage({ type: 'error', text: e.message });
    } finally {
      setBusy(null);
    }
  }

  return (
    <section>
      <h2>Review Reports</h2>
      <p className="muted">Approve reports that are scams so they appear in the public list, or reject them.</p>

      <div className="tabs" role="tablist" aria-label="Report status">
        {TABS.map((t) => (
          <button key={t} role="tab" aria-selected={status === t} className={status === t ? 'tab active' : 'tab'}
            onClick={() => { setMessage(null); setStatus(t); }}>{STATUS_LABELS[t]}</button>
        ))}
      </div>

      {message && <div className={`alert alert-${message.type}`} role={message.type === 'error' ? 'alert' : 'status'}>{message.text}</div>}
      {!items && <div className="muted">Loading…</div>}
      {items && items.length === 0 && <div className="card empty">No {STATUS_LABELS[status].toLowerCase()} reports.</div>}
      {items && items.map((r) => (
        <article key={r.id} className="card report-card">
          <div className="report-head">
            <code className="url-cell">{r.url}</code>
            <StatusBadge status={r.status} />
          </div>
          <dl className="details">
            <dt>Category</dt><dd>{CATEGORY_LABELS[r.category]}</dd>
            <dt>Description</dt><dd>{r.description || <span className="muted">None</span>}</dd>
            <dt>Reported by</dt><dd>{r.reporterName} ({r.reporterEmail}) on {formatDateTime(r.createdAt)}</dd>
            <dt>Latest verdict</dt>
            <dd><VerdictBadge verdict={r.latestVerdict} /> {r.latestCheckedAt && <span className="muted">checked {formatDateTime(r.latestCheckedAt)}</span>}</dd>
            {r.reviewedAt && (<><dt>Reviewed</dt><dd>{r.reviewedByName} on {formatDateTime(r.reviewedAt)}</dd></>)}
          </dl>
          {(r.status === 'PENDING' || r.status === 'APPROVED') && (
            <div className="actions">
              {r.status === 'PENDING' && (
                <>
                  <button className="btn" disabled={busy === r.id} onClick={() => act(r, 'APPROVE')}>Approve</button>
                  <button className="btn btn-outline" disabled={busy === r.id} onClick={() => act(r, 'REJECT')}>Reject</button>
                </>
              )}
              {r.status === 'APPROVED' && (
                <button className="btn btn-outline" disabled={busy === r.id} onClick={() => act(r, 'REMOVE')}>Remove from public list</button>
              )}
              <button className="btn btn-outline" disabled={busy === r.id} onClick={() => act(r, 'RECHECK')}>
                {busy === r.id ? 'Working…' : 'Re-check link'}
              </button>
            </div>
          )}
        </article>
      ))}
    </section>
  );
}

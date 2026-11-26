import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api.js';
import { useAuth } from '../auth/AuthContext.jsx';
import Field from '../components/Field.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import { CATEGORY_LABELS, formatDateTime } from '../format.js';

const MAX_DESCRIPTION = 500;

export default function ReportPage() {
  const { sessionExpired } = useAuth();
  const [params] = useSearchParams();
  const [url, setUrl] = useState(params.get('url') || '');
  const [category, setCategory] = useState('');
  const [description, setDescription] = useState('');
  const [errors, setErrors] = useState({});
  const [message, setMessage] = useState(null);
  const [saving, setSaving] = useState(false);
  const [mine, setMine] = useState(null);

  const loadMine = useCallback(() => {
    api('/api/reports/mine').then(setMine).catch((e) => e.status === 401 && sessionExpired());
  }, [sessionExpired]);
  useEffect(loadMine, [loadMine]);

  async function onSubmit(e) {
    e.preventDefault();
    const found = {};
    if (!url.trim()) found.url = 'Please enter the link you want to report';
    if (!category) found.category = 'Please choose a category';
    if (description.length > MAX_DESCRIPTION) found.description = `Description must be at most ${MAX_DESCRIPTION} characters`;
    setErrors(found);
    setMessage(null);
    if (Object.keys(found).length) return;
    setSaving(true);
    try {
      await api('/api/reports', { method: 'POST', body: { url: url.trim(), category, description: description.trim() } });
      setMessage({ type: 'success', text: 'Thank you. Your report was submitted and is waiting for an administrator to review it.' });
      setUrl(''); setCategory(''); setDescription('');
      loadMine();
    } catch (err) {
      if (err.status === 401) return sessionExpired();
      setErrors(err.fieldErrors || {});
      setMessage({ type: 'error', text: err.message });
    } finally {
      setSaving(false);
    }
  }

  return (
    <section>
      <h2>Report a Scam Link</h2>
      <p className="muted">Approved reports appear in the public list of scam links so others are warned.</p>

      <div className="card">
        {message && <div className={`alert alert-${message.type}`} role={message.type === 'error' ? 'alert' : 'status'}>{message.text}</div>}
        <form className="form" onSubmit={onSubmit} noValidate>
          <Field id="url" label="Link" type="text" inputMode="url" spellCheck="false" value={url}
            onChange={(e) => setUrl(e.target.value)} maxLength={2048} error={errors.url} required />
          <div className="field">
            <label htmlFor="category">Category</label>
            <select id="category" value={category} onChange={(e) => setCategory(e.target.value)}
              aria-invalid={Boolean(errors.category)} aria-describedby={errors.category ? 'category-error' : undefined}>
              <option value="">Choose a category…</option>
              {Object.entries(CATEGORY_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
            {errors.category && <span id="category-error" className="field-error">{errors.category}</span>}
          </div>
          <div className="field">
            <label htmlFor="description">Description (optional)</label>
            <textarea id="description" rows={4} value={description} maxLength={MAX_DESCRIPTION}
              onChange={(e) => setDescription(e.target.value)} placeholder="Where did you get this link? What did it ask for?"
              aria-describedby="description-count" />
            <span id="description-count" className={errors.description ? 'field-error' : 'field-hint'}>
              {errors.description || `${description.length}/${MAX_DESCRIPTION} characters`}
            </span>
          </div>
          <button className="btn" type="submit" disabled={saving}>{saving ? 'Submitting…' : 'Submit report'}</button>
        </form>
      </div>

      <div className="card">
        <h3>My reports</h3>
        {!mine && <p className="muted">Loading…</p>}
        {mine && mine.length === 0 && <p className="muted">You have not reported any links yet.</p>}
        {mine && mine.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Link</th><th>Category</th><th>Status</th><th>Reported</th></tr></thead>
              <tbody>
                {mine.map((r) => (
                  <tr key={r.id}>
                    <td className="url-cell"><code>{r.url}</code></td>
                    <td>{CATEGORY_LABELS[r.category]}</td>
                    <td><StatusBadge status={r.status} /></td>
                    <td>{formatDateTime(r.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

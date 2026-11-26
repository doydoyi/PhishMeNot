import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api.js';
import { useAuth } from '../auth/AuthContext.jsx';
import VerdictBadge from '../components/VerdictBadge.jsx';
import { formatDateTime } from '../format.js';

const MAX_URL = 2048;

export default function CheckLinkPage() {
  const { sessionExpired } = useAuth();
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [checking, setChecking] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    if (!url.trim()) {
      setError('Please enter a link to check.');
      return;
    }
    setChecking(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api('/api/verifications', { method: 'POST', body: { url: url.trim() } }));
    } catch (err) {
      if (err.status === 401) return sessionExpired();
      setError(err.fieldErrors?.url || err.message);
    } finally {
      setChecking(false);
    }
  }

  return (
    <section>
      <h2>Check a Link</h2>
      <p className="muted">
        Paste a link you received by SMS, email, Messenger or social media. PhishMeNot checks it against VirusTotal and
        Google Safe Browsing. The link is never opened.
      </p>

      <form className="check-form" onSubmit={onSubmit} noValidate>
        <label htmlFor="url" className="sr-only">Link to check</label>
        <input id="url" type="text" inputMode="url" autoComplete="off" spellCheck="false" placeholder="e.g. gcash-rewards.example.com/claim"
          value={url} onChange={(e) => setUrl(e.target.value)} maxLength={MAX_URL}
          aria-invalid={Boolean(error)} aria-describedby={error ? 'url-error' : undefined} />
        <button className="btn" type="submit" disabled={checking}>{checking ? 'Checking…' : 'Check link'}</button>
      </form>
      {error && <div id="url-error" className="alert alert-error" role="alert">{error}</div>}
      {checking && (
        <div className="alert alert-info" role="status">
          <span className="spinner" aria-hidden="true" /> Checking with VirusTotal and Google Safe Browsing. This can take up to 30 seconds…
        </div>
      )}

      {result && <ResultCard result={result} onReset={() => { setResult(null); setUrl(''); }} />}
    </section>
  );
}

export function ResultCard({ result, onReset }) {
  return (
    <div className={`card result-card result-${result.verdict}`} aria-live="polite">
      <div className="result-head">
        <VerdictBadge verdict={result.verdict} large />
        {result.partialCheck && <span className="badge">Partial check</span>}
      </div>
      <p className="checked-url">
        <span className="muted">Checked link: </span>
        <code>{result.submittedUrl}</code>
      </p>
      <p>{result.explanation}</p>

      {result.safetyTips.length > 0 && (
        <div className="tips">
          <h3>Stay safe</h3>
          <ul>{result.safetyTips.map((tip) => <li key={tip}>{tip}</li>)}</ul>
        </div>
      )}

      <dl className="details">
        <dt>VirusTotal</dt>
        <dd>
          {result.vtTotalEngines == null ? 'Not available for this check'
            : `${result.vtMaliciousCount} malicious, ${result.vtSuspiciousCount} suspicious, out of ${result.vtTotalEngines} engines`}
        </dd>
        <dt>Google Safe Browsing</dt>
        <dd>
          {result.partialCheck && result.threatTypes.length === 0 && result.vtTotalEngines != null ? 'Not available for this check'
            : result.threatTypes.length ? result.threatTypes.join(', ').toLowerCase().replaceAll('_', ' ') : 'No match'}
        </dd>
        <dt>Checked</dt>
        <dd>{formatDateTime(result.checkedAt)}{result.cached && ' (saved result from the last 24 hours)'}</dd>
      </dl>

      <div className="actions">
        {result.verdict !== 'SAFE' && (
          <Link className="btn btn-danger" to={`/report?url=${encodeURIComponent(result.normalizedUrl)}`}>Report this link</Link>
        )}
        {onReset && <button className="btn btn-outline" type="button" onClick={onReset}>Check another link</button>}
      </div>
    </div>
  );
}

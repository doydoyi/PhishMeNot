import { useState } from 'react';
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom';
import { GOOGLE_LOGIN_URL } from '../api.js';
import { homePathFor, useAuth } from '../auth/AuthContext.jsx';
import Field from '../components/Field.jsx';

// Messages for the error codes sent back by the backend's LoginFailureHandler.
const ERROR_MESSAGES = {
  access_denied: 'Sign-in was cancelled. Please try again and allow access to continue.',
  email_not_verified: 'Your Google email address is not verified. Verify it with Google, then try again.',
  invalid_profile: 'Google did not share the required account details (name and email). Please try again.',
  account_conflict: 'This email is already registered with a password. Sign in with your email and password instead.',
  login_failed: 'Sign-in failed. Please check your Google credentials and try again.',
};

export function AuthCard({ children }) {
  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo" aria-hidden="true">🛡️</div>
        <h1>PhishMeNot</h1>
        <p className="muted">Suspicious Link and Phishing Checker</p>
        {children}
      </div>
    </div>
  );
}

export default function LoginPage() {
  const { user, loading, loginWithPassword } = useAuth();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const errorCode = params.get('error');
  const loggedOut = params.has('loggedOut');
  const reset = params.has('reset');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [formError, setFormError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  if (loading) return <div className="center muted">Loading…</div>;
  if (user) return <Navigate to={homePathFor(user)} replace />;

  async function onSubmit(e) {
    e.preventDefault();
    if (!email.trim() || !password) {
      setFormError('Enter your email and password.');
      return;
    }
    setSubmitting(true);
    setFormError(null);
    try {
      const signedIn = await loginWithPassword(email.trim(), password);
      navigate(homePathFor(signedIn), { replace: true });
    } catch (err) {
      setFormError(err.message);
      setPassword('');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthCard>
      {errorCode && (
        <div className="alert alert-error" role="alert">
          {ERROR_MESSAGES[errorCode] || ERROR_MESSAGES.login_failed}
        </div>
      )}
      {loggedOut && !errorCode && <div className="alert alert-info" role="status">You have been signed out.</div>}
      {reset && <div className="alert alert-success" role="status">Password reset. Sign in with your new password.</div>}
      {formError && <div className="alert alert-error" role="alert">{formError}</div>}

      <form className="form" onSubmit={onSubmit} noValidate>
        <Field id="email" label="Email" type="email" autoComplete="email" value={email}
          onChange={(e) => setEmail(e.target.value)} maxLength={255} required />
        <Field id="password" label="Password" type="password" autoComplete="current-password" value={password}
          onChange={(e) => setPassword(e.target.value)} maxLength={72} required />
        <div className="form-row-end"><Link to="/forgot-password">Forgot password?</Link></div>
        <button className="btn btn-block" type="submit" disabled={submitting}>
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>

      <div className="divider"><span>or</span></div>

      <a className="btn btn-google" href={GOOGLE_LOGIN_URL}>
        <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
          <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/>
          <path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/>
          <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z"/>
          <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/>
        </svg>
        Sign in with Google
      </a>

      <p className="fine-print">
        New here? <Link to="/register">Create an account</Link> with your email, or sign in with Google.
      </p>
      <p className="fine-print"><Link to="/scam-links">View the list of reported scam links</Link> without signing in.</p>
    </AuthCard>
  );
}

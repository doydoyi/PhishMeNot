import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api.js';
import Field from '../components/Field.jsx';
import { AuthCard } from './LoginPage.jsx';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState(null);
  const [sent, setSent] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    if (!/^\S+@\S+\.\S+$/.test(email.trim())) {
      setError('Enter a valid email address');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const result = await api('/api/auth/forgot-password', { method: 'POST', body: { email: email.trim() } });
      setSent(result.message);
    } catch (err) {
      setError(err.fieldErrors?.email || err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthCard>
      <h2 className="card-title">Forgot your password?</h2>
      {sent ? (
        <div className="alert alert-success" role="status">{sent}</div>
      ) : (
        <>
          <p className="muted left">Enter the email you registered with and we will send you a link to reset your password.</p>
          <form className="form" onSubmit={onSubmit} noValidate>
            <Field id="email" label="Email" type="email" autoComplete="email" value={email}
              onChange={(e) => setEmail(e.target.value)} maxLength={255} error={error} required />
            <button className="btn btn-block" type="submit" disabled={submitting}>
              {submitting ? 'Sending…' : 'Send reset link'}
            </button>
          </form>
        </>
      )}
      <p className="fine-print"><Link to="/login">Back to sign in</Link></p>
    </AuthCard>
  );
}

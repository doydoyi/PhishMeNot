import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api.js';
import Field, { PASSWORD_HINT, passwordProblem } from '../components/Field.jsx';
import { AuthCard } from './LoginPage.jsx';

export default function ResetPasswordPage() {
  const [params] = useSearchParams();
  const token = params.get('token') || '';
  const navigate = useNavigate();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    const found = {};
    const problem = passwordProblem(newPassword);
    if (problem) found.newPassword = problem;
    if (confirmPassword !== newPassword) found.confirmPassword = 'The passwords do not match';
    setErrors(found);
    setFormError(null);
    if (Object.keys(found).length) return;
    setSubmitting(true);
    try {
      await api('/api/auth/reset-password', { method: 'POST', body: { token, newPassword, confirmPassword } });
      navigate('/login?reset=1', { replace: true });
    } catch (err) {
      setErrors(err.fieldErrors || {});
      setFormError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthCard>
      <h2 className="card-title">Choose a new password</h2>
      {!token ? (
        <div className="alert alert-error" role="alert">
          This reset link is incomplete. <Link to="/forgot-password">Request a new link</Link>.
        </div>
      ) : (
        <>
          {formError && (
            <div className="alert alert-error" role="alert">
              {formError} {formError.includes('Request a new one') && <Link to="/forgot-password">Request a new link</Link>}
            </div>
          )}
          <form className="form" onSubmit={onSubmit} noValidate>
            <Field id="newPassword" label="New password" type="password" autoComplete="new-password" value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)} maxLength={72} error={errors.newPassword} hint={PASSWORD_HINT} required />
            <Field id="confirmPassword" label="Confirm new password" type="password" autoComplete="new-password"
              value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} maxLength={72}
              error={errors.confirmPassword} required />
            <button className="btn btn-block" type="submit" disabled={submitting}>
              {submitting ? 'Saving…' : 'Reset password'}
            </button>
          </form>
        </>
      )}
      <p className="fine-print"><Link to="/login">Back to sign in</Link></p>
    </AuthCard>
  );
}

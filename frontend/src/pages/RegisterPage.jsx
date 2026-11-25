import { useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { api } from '../api.js';
import { homePathFor, useAuth } from '../auth/AuthContext.jsx';
import Field, { PASSWORD_HINT, passwordProblem } from '../components/Field.jsx';
import { AuthCard } from './LoginPage.jsx';

const EMPTY = { name: '', email: '', password: '', confirmPassword: '' };

export default function RegisterPage() {
  const { user, loading, loginWithPassword } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState(EMPTY);
  const [errors, setErrors] = useState({});
  const [formError, setFormError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  if (loading) return <div className="center muted">Loading…</div>;
  if (user) return <Navigate to={homePathFor(user)} replace />;

  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value });

  function validate() {
    const next = {};
    if (!form.name.trim()) next.name = 'Name is required';
    if (!/^\S+@\S+\.\S+$/.test(form.email.trim())) next.email = 'Enter a valid email address';
    const problem = passwordProblem(form.password);
    if (problem) next.password = problem;
    if (form.confirmPassword !== form.password) next.confirmPassword = 'The passwords do not match';
    return next;
  }

  async function onSubmit(e) {
    e.preventDefault();
    const found = validate();
    setErrors(found);
    setFormError(null);
    if (Object.keys(found).length) return;
    setSubmitting(true);
    try {
      await api('/api/auth/register', { method: 'POST', body: { ...form, name: form.name.trim(), email: form.email.trim() } });
      const signedIn = await loginWithPassword(form.email.trim(), form.password);
      navigate(homePathFor(signedIn), { replace: true });
    } catch (err) {
      setErrors(err.fieldErrors || {});
      setFormError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthCard>
      <h2 className="card-title">Create your account</h2>
      {formError && <div className="alert alert-error" role="alert">{formError}</div>}
      <form className="form" onSubmit={onSubmit} noValidate>
        <Field id="name" label="Full name" autoComplete="name" value={form.name} onChange={set('name')}
          maxLength={150} error={errors.name} required />
        <Field id="email" label="Email" type="email" autoComplete="email" value={form.email} onChange={set('email')}
          maxLength={255} error={errors.email} required />
        <Field id="password" label="Password" type="password" autoComplete="new-password" value={form.password}
          onChange={set('password')} maxLength={72} error={errors.password} hint={PASSWORD_HINT} required />
        <Field id="confirmPassword" label="Confirm password" type="password" autoComplete="new-password"
          value={form.confirmPassword} onChange={set('confirmPassword')} maxLength={72} error={errors.confirmPassword} required />
        <button className="btn btn-block" type="submit" disabled={submitting}>
          {submitting ? 'Creating account…' : 'Create account'}
        </button>
      </form>
      <p className="fine-print">Already have an account? <Link to="/login">Sign in</Link></p>
    </AuthCard>
  );
}

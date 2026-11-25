import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api.js';
import { useAuth } from '../auth/AuthContext.jsx';
import Avatar from '../components/Avatar.jsx';
import Field, { PASSWORD_HINT, passwordProblem } from '../components/Field.jsx';
import { formatDateTime } from '../format.js';

export default function ProfilePage() {
  const { user } = useAuth();
  return (
    <section>
      <h2>My Profile</h2>
      <p className="muted">View and update your account details.</p>
      <ProfileForm key={user.id} />
      <PasswordSection />
    </section>
  );
}

function ProfileForm() {
  const { user, setUser, sessionExpired } = useAuth();
  const [name, setName] = useState(user.name);
  const [pictureUrl, setPictureUrl] = useState(user.profilePictureUrl || '');
  const [errors, setErrors] = useState({});
  const [message, setMessage] = useState(null);
  const [saving, setSaving] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    const found = {};
    if (!name.trim()) found.name = 'Name is required';
    if (pictureUrl.trim() && !/^https:\/\/\S+$/.test(pictureUrl.trim())) found.profilePictureUrl = 'Picture URL must start with https://';
    setErrors(found);
    setMessage(null);
    if (Object.keys(found).length) return;
    setSaving(true);
    try {
      const updated = await api('/api/me/profile', {
        method: 'PUT', body: { name: name.trim(), profilePictureUrl: pictureUrl.trim() },
      });
      setUser(updated);
      setName(updated.name);
      setMessage({ type: 'success', text: 'Profile saved.' });
    } catch (err) {
      if (err.status === 401) return sessionExpired();
      setErrors(err.fieldErrors || {});
      setMessage({ type: 'error', text: err.message });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card">
      <div className="profile-card">
        <Avatar user={{ ...user, profilePictureUrl: pictureUrl.trim() || null }} size={72} />
        <div>
          <h3>{user.name}</h3>
          <p className="muted">{user.email}</p>
          <span className={`badge ${user.role === 'ADMIN' ? 'badge-admin' : ''}`}>
            {user.role === 'ADMIN' ? 'Administrator' : 'General User'}
          </span>
        </div>
      </div>
      <dl className="details">
        <dt>Sign-in methods</dt>
        <dd>{[user.googleLinked && 'Google', user.hasPassword && 'Email & password'].filter(Boolean).join(', ')}</dd>
        <dt>Member since</dt><dd>{formatDateTime(user.createdAt)}</dd>
        <dt>Last sign-in</dt><dd>{formatDateTime(user.lastLoginAt)}</dd>
      </dl>

      <h3 className="section-title">Edit profile</h3>
      {message && (
        <div className={`alert alert-${message.type}`} role={message.type === 'error' ? 'alert' : 'status'}>{message.text}</div>
      )}
      <form className="form" onSubmit={onSubmit} noValidate>
        <Field id="name" label="Full name" autoComplete="name" value={name} onChange={(e) => setName(e.target.value)}
          maxLength={150} error={errors.name} required />
        <Field id="email" label="Email (cannot be changed)" type="email" value={user.email} readOnly disabled />
        <Field id="profilePictureUrl" label="Profile picture URL (optional)" type="url" value={pictureUrl}
          onChange={(e) => setPictureUrl(e.target.value)} maxLength={500} error={errors.profilePictureUrl}
          hint="An https:// image link. Leave empty to show your initial." />
        <button className="btn" type="submit" disabled={saving}>{saving ? 'Saving…' : 'Save changes'}</button>
      </form>
    </div>
  );
}

const EMPTY = { currentPassword: '', newPassword: '', confirmPassword: '' };

function PasswordSection() {
  const { user, sessionExpired } = useAuth();
  const [form, setForm] = useState(EMPTY);
  const [errors, setErrors] = useState({});
  const [message, setMessage] = useState(null);
  const [saving, setSaving] = useState(false);

  if (!user.hasPassword) {
    return (
      <div className="card">
        <h3 className="section-title">Password</h3>
        <p className="muted">
          You sign in with Google, so your account has no PhishMeNot password. To create one, sign out and use{' '}
          <Link to="/forgot-password">Forgot password</Link> with {user.email}.
        </p>
      </div>
    );
  }

  const set = (key) => (e) => setForm({ ...form, [key]: e.target.value });

  async function onSubmit(e) {
    e.preventDefault();
    const found = {};
    if (!form.currentPassword) found.currentPassword = 'Current password is required';
    const problem = passwordProblem(form.newPassword);
    if (problem) found.newPassword = problem;
    if (form.confirmPassword !== form.newPassword) found.confirmPassword = 'The new passwords do not match';
    setErrors(found);
    setMessage(null);
    if (Object.keys(found).length) return;
    setSaving(true);
    try {
      const result = await api('/api/me/password', { method: 'PUT', body: form });
      setForm(EMPTY);
      setMessage({ type: 'success', text: result.message });
    } catch (err) {
      if (err.status === 401) return sessionExpired();
      setErrors(err.fieldErrors || {});
      setMessage({ type: 'error', text: err.message });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card">
      <h3 className="section-title">Change password</h3>
      {message && (
        <div className={`alert alert-${message.type}`} role={message.type === 'error' ? 'alert' : 'status'}>{message.text}</div>
      )}
      <form className="form" onSubmit={onSubmit} noValidate>
        <Field id="currentPassword" label="Current password" type="password" autoComplete="current-password"
          value={form.currentPassword} onChange={set('currentPassword')} maxLength={72} error={errors.currentPassword} required />
        <Field id="newPassword" label="New password" type="password" autoComplete="new-password" value={form.newPassword}
          onChange={set('newPassword')} maxLength={72} error={errors.newPassword} hint={PASSWORD_HINT} required />
        <Field id="confirmPassword" label="Confirm new password" type="password" autoComplete="new-password"
          value={form.confirmPassword} onChange={set('confirmPassword')} maxLength={72} error={errors.confirmPassword} required />
        <button className="btn" type="submit" disabled={saving}>{saving ? 'Saving…' : 'Change password'}</button>
      </form>
    </div>
  );
}

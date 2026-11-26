import { Link, Outlet } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext.jsx';
import Layout from './Layout.jsx';

/** Pages open to guests (the public scam list): full navigation when signed in, a simple header otherwise. */
export default function GuestLayout() {
  const { user, loading } = useAuth();
  if (loading) return <div className="center muted">Loading…</div>;
  if (user) return <Layout />;
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand"><span className="logo" aria-hidden="true">🛡️</span> PhishMeNot</div>
        <nav className="nav" />
        <Link className="btn" to="/login">Sign in to check a link</Link>
      </header>
      <main className="content"><Outlet /></main>
    </div>
  );
}

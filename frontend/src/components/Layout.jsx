import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext.jsx';
import Avatar from './Avatar.jsx';

const USER_LINKS = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/check', label: 'Check a Link' },
  { to: '/history', label: 'History' },
  { to: '/report', label: 'Report a Link' },
  { to: '/scam-links', label: 'Scam Links' },
  { to: '/profile', label: 'Profile' },
];
const ADMIN_LINKS = [
  { to: '/admin', label: 'Admin Dashboard', end: true },
  { to: '/admin/reports', label: 'Review Reports' },
  { to: '/admin/users', label: 'Users' },
  { to: '/check', label: 'Check a Link' },
  { to: '/history', label: 'History' },
  { to: '/scam-links', label: 'Scam Links' },
  { to: '/dashboard', label: 'My Account' },
  { to: '/profile', label: 'Profile' },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const links = user?.role === 'ADMIN' ? ADMIN_LINKS : USER_LINKS;

  async function handleLogout() {
    await logout();
    navigate('/login?loggedOut=1', { replace: true });
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo" aria-hidden="true">🛡️</span> PhishMeNot
        </div>
        <nav className="nav">
          {links.map((l) => (
            <NavLink key={l.to} to={l.to} end={l.end} className={({ isActive }) => (isActive ? 'active' : '')}>
              {l.label}
            </NavLink>
          ))}
        </nav>
        <div className="who">
          <Avatar user={user} size={32} />
          <span className="who-name">{user?.name}</span>
          <span className={`badge ${user?.role === 'ADMIN' ? 'badge-admin' : ''}`}>
            {user?.role === 'ADMIN' ? 'Administrator' : 'General User'}
          </span>
          <button className="btn btn-outline" onClick={handleLogout}>Sign out</button>
        </div>
      </header>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}

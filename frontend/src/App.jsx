import { Navigate, Route, Routes } from 'react-router-dom';
import { homePathFor, useAuth } from './auth/AuthContext.jsx';
import ProtectedRoute from './components/ProtectedRoute.jsx';
import Layout from './components/Layout.jsx';
import LoginPage from './pages/LoginPage.jsx';
import UserDashboard from './pages/UserDashboard.jsx';
import AdminDashboard from './pages/AdminDashboard.jsx';
import AdminUsers from './pages/AdminUsers.jsx';
import ForbiddenPage from './pages/ForbiddenPage.jsx';
import NotFoundPage from './pages/NotFoundPage.jsx';
import RegisterPage from './pages/RegisterPage.jsx';
import ForgotPasswordPage from './pages/ForgotPasswordPage.jsx';
import ResetPasswordPage from './pages/ResetPasswordPage.jsx';
import ProfilePage from './pages/ProfilePage.jsx';
import GuestLayout from './components/GuestLayout.jsx';
import CheckLinkPage from './pages/CheckLinkPage.jsx';
import HistoryPage from './pages/HistoryPage.jsx';
import ReportPage from './pages/ReportPage.jsx';
import PublicReportsPage from './pages/PublicReportsPage.jsx';
import AdminReportsPage from './pages/AdminReportsPage.jsx';

function HomeRedirect() {
  const { user, loading } = useAuth();
  if (loading) return <div className="center muted">Loading…</div>;
  return <Navigate to={homePathFor(user)} replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<HomeRedirect />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/forbidden" element={<ForbiddenPage />} />

      {/* Public list of approved scam reports: open to guests (FR-032) */}
      <Route element={<GuestLayout />}>
        <Route path="/scam-links" element={<PublicReportsPage />} />
      </Route>

      {/* General User area (Administrators inherit General User use cases) */}
      <Route element={<ProtectedRoute roles={['USER', 'ADMIN']} />}>
        <Route element={<Layout />}>
          <Route path="/dashboard" element={<UserDashboard />} />
          <Route path="/profile" element={<ProfilePage />} />
          <Route path="/check" element={<CheckLinkPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/report" element={<ReportPage />} />
        </Route>
      </Route>

      {/* Administrator-only area */}
      <Route element={<ProtectedRoute roles={['ADMIN']} />}>
        <Route element={<Layout />}>
          <Route path="/admin" element={<AdminDashboard />} />
          <Route path="/admin/users" element={<AdminUsers />} />
          <Route path="/admin/reports" element={<AdminReportsPage />} />
        </Route>
      </Route>

      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}

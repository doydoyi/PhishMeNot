import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api.js';
import { useAuth } from '../auth/AuthContext.jsx';
import DailyChart from '../components/DailyChart.jsx';
import UserTable from '../components/UserTable.jsx';
import VerdictBadge from '../components/VerdictBadge.jsx';

export default function AdminDashboard() {
  const { sessionExpired } = useAuth();
  const [data, setData] = useState(null);
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    Promise.all([api('/api/admin/dashboard'), api('/api/admin/statistics')])
      .then(([dashboard, statistics]) => { setData(dashboard); setStats(statistics); })
      .catch((e) => (e.status === 401 ? sessionExpired() : setError(e.message)));
  }, [sessionExpired]);

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!data || !stats) return <div className="muted">Loading admin dashboard…</div>;

  return (
    <section>
      <h2>Administrator Dashboard</h2>
      <p className="muted">Link verification activity, scam reports and accounts.</p>

      <h3 className="section-title">Link verifications</h3>
      <div className="stats">
        <Stat label="Total verifications" value={stats.totalVerifications} />
        {['SAFE', 'SUSPICIOUS', 'MALICIOUS'].map((v) => (
          <div key={v} className="card stat">
            <span className="stat-label"><VerdictBadge verdict={v} /></span>
            <span className="stat-value">{stats.verificationsByVerdict[v]}</span>
          </div>
        ))}
      </div>
      <div className="card">
        <DailyChart title="Verifications per day, last 30 days" days={stats.verificationsPerDay} />
      </div>

      <h3 className="section-title">Scam reports</h3>
      <div className="stats">
        <div className="card stat">
          <span className="stat-label">Pending review</span>
          <span className="stat-value">{stats.reportsByStatus.PENDING}</span>
          <Link to="/admin/reports">Review reports →</Link>
        </div>
        <Stat label="Approved (public)" value={stats.reportsByStatus.APPROVED} />
        <Stat label="Rejected" value={stats.reportsByStatus.REJECTED} />
        <Stat label="Removed" value={stats.reportsByStatus.REMOVED} />
      </div>

      <h3 className="section-title">Accounts</h3>

      <div className="stats">
        <Stat label="Total users" value={data.totalUsers} />
        <Stat label="General users" value={data.generalUsers} />
        <Stat label="Administrators" value={data.administrators} />
        <Stat label="New in last 7 days" value={data.newUsersLast7Days} />
      </div>

      <div className="card">
        <div className="card-head">
          <h3>Newest accounts</h3>
          <Link to="/admin/users">View all users →</Link>
        </div>
        <UserTable users={data.recentUsers} />
      </div>
    </section>
  );
}

function Stat({ label, value }) {
  return (
    <div className="card stat">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </div>
  );
}

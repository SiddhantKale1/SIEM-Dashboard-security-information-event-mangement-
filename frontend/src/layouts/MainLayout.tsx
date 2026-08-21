import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { Shield, LayoutDashboard, Server, FileText, LogOut, Activity } from 'lucide-react';

export default function MainLayout() {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/login');
  };

  const navItems = [
    { name: 'Overview',  path: '/',        icon: LayoutDashboard },
    { name: 'Devices',   path: '/devices', icon: Server },
    { name: 'Logs',      path: '/logs',    icon: FileText },
  ];

  return (
    <div style={{ display: 'flex', height: '100vh', background: 'var(--color-dark-bg)', overflow: 'hidden' }}>

      {/* ── Sidebar ── */}
      <aside style={{
        width: 230,
        background: 'rgba(8, 11, 16, 0.95)',
        borderRight: '1px solid var(--color-dark-border)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
      }}>

        {/* Logo */}
        <div style={{
          height: 60,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '0 20px',
          borderBottom: '1px solid var(--color-dark-border)',
        }}>
          <div style={{
            width: 32, height: 32,
            background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
            borderRadius: 8,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 16px rgba(59,130,246,0.35)',
          }}>
            <Shield size={16} color="white" />
          </div>
          <span style={{ fontWeight: 700, fontSize: '0.95rem', color: '#f1f5f9', letterSpacing: '-0.01em' }}>
            SIEM<span style={{ color: '#3b82f6' }}>MVP</span>
          </span>
        </div>

        {/* Live indicator */}
        <div style={{
          margin: '14px 16px 6px',
          padding: '8px 12px',
          background: 'rgba(34,197,94,0.06)',
          border: '1px solid rgba(34,197,94,0.15)',
          borderRadius: 8,
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <Activity size={13} color="#4ade80" />
          <span style={{ fontSize: '0.75rem', color: '#4ade80', fontWeight: 500 }}>System Active</span>
          <span className="status-dot online" style={{ marginLeft: 'auto' }} />
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 2 }}>
          <p className="section-label" style={{ padding: '12px 6px 6px' }}>Navigation</p>
          {navItems.map((item) => (
            <NavLink
              key={item.name}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) => `sidebar-nav-link${isActive ? ' active' : ''}`}
            >
              <item.icon size={16} />
              {item.name}
            </NavLink>
          ))}
        </nav>

        {/* Logout */}
        <div style={{ padding: '12px', borderTop: '1px solid var(--color-dark-border)' }}>
          <button
            onClick={handleLogout}
            style={{
              width: '100%',
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 12px',
              borderRadius: 10,
              background: 'transparent',
              border: 'none',
              color: '#475569',
              fontSize: '0.875rem',
              fontWeight: 500,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              fontFamily: 'inherit',
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(239,68,68,0.06)'; (e.currentTarget as HTMLElement).style.color = '#f87171'; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; (e.currentTarget as HTMLElement).style.color = '#475569'; }}
          >
            <LogOut size={16} />
            Sign Out
          </button>
        </div>
      </aside>

      {/* ── Main Content ── */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative' }}>
        {/* Glow blobs */}
        <div style={{
          position: 'absolute', top: '-15%', right: '-5%',
          width: '45%', height: '45%', borderRadius: '50%',
          background: 'rgba(59,130,246,0.04)', filter: 'blur(100px)', pointerEvents: 'none',
        }} />
        <div style={{
          position: 'absolute', bottom: '-10%', left: '20%',
          width: '30%', height: '30%', borderRadius: '50%',
          background: 'rgba(139,92,246,0.03)', filter: 'blur(80px)', pointerEvents: 'none',
        }} />

        <div style={{ flex: 1, overflowY: 'auto', padding: '28px 32px', position: 'relative', zIndex: 1 }}>
          <Outlet />
        </div>
      </main>
    </div>
  );
}

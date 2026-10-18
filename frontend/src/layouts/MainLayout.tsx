import { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutGrid, 
  Radio, 
  Terminal, 
  Flame, 
  LogOut, 
  Sparkles,
  Monitor
} from 'lucide-react';
import api from '../services/api';
import ChangePasswordModal from '../components/ChangePasswordModal';

export default function MainLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const [user, setUser] = useState<{ username: string; must_change_password?: boolean } | null>(null);
  const [activeThreats, setActiveThreats] = useState<number>(0);
  const [activeNetworkInfo, setActiveNetworkInfo] = useState<{ subnet?: string; active_devices_count?: number }>({});

  const fetchLiveStatus = async () => {
    try {
      const [threatsRes, trafficRes] = await Promise.all([
        api.get('/anomalies/stats').catch(() => ({ data: { active_threats: 0 } })),
        api.get('/network/traffic').catch(() => ({ data: { active_devices_count: 0, network: { subnet: '192.168.1.0/24' } } }))
      ]);
      setActiveThreats(threatsRes.data.active_threats || 0);
      setActiveNetworkInfo({
        subnet: trafficRes.data.network?.subnet,
        active_devices_count: trafficRes.data.active_devices_count
      });
    } catch {
      // ignore in background
    }
  };

  useEffect(() => {
    api.get('/auth/me')
      .then(res => setUser(res.data))
      .catch(() => handleLogout());

    fetchLiveStatus();
    const interval = setInterval(fetchLiveStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/login');
  };

  const navItems = [
    { name: 'Command Bento',   path: '/',           icon: LayoutGrid,    badge: null },
    { name: 'AI Threat Radar', path: '/threats',    icon: ShieldAlert,   badge: activeThreats > 0 ? activeThreats : null, badgeColor: '#f43f5e' },
    { name: 'Network Traffic', path: '/network',    icon: Radio,         badge: activeNetworkInfo.active_devices_count !== undefined ? `${activeNetworkInfo.active_devices_count} live` : null, badgeColor: '#06b6d4' },
    { name: 'Enrolled Devices', path: '/endpoints', icon: Monitor,       badge: null },
    { name: 'Attack Lab',      path: '/simulator',  icon: Flame,         badge: 'SIM', badgeColor: '#8b5cf6' },
    { name: 'Log Streamer',    path: '/logs',       icon: Terminal,      badge: null },
  ];

  return (
    <div style={{ display: 'flex', height: '100vh', background: '#070a11', color: '#f1f5f9', overflow: 'hidden' }}>

      {/* ── Cyber-Neobrutalist Sidebar ── */}
      <aside style={{
        width: 250,
        background: '#0a0e18',
        borderRight: '2.5px solid #1e293b',
        boxShadow: '4px 0px 0px #020408',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        zIndex: 20
      }}>

        {/* Brand Header */}
        <div style={{
          height: 68,
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          padding: '0 18px',
          borderBottom: '2.5px solid #1e293b',
          background: '#0c111c'
        }}>
          <div style={{
            width: 38,
            height: 38,
            background: '#8b5cf6',
            borderRadius: 8,
            border: '2px solid #000',
            boxShadow: '3px 3px 0px #000',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0
          }}>
            <Sparkles size={20} color="#ffffff" />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: '1.05rem', letterSpacing: '-0.02em', color: '#f8fafc', lineHeight: 1.1 }}>
              AETHER<span style={{ color: '#06b6d4' }}>SIEM</span>
            </div>
            <div style={{ fontSize: '0.68rem', fontFamily: 'JetBrains Mono, monospace', color: '#8b5cf6', fontWeight: 600 }}>
              AI DEFENSE MATRIX
            </div>
          </div>
        </div>

        {/* Live Network Pill */}
        <div style={{
          margin: '14px 14px 6px',
          padding: '10px 12px',
          background: '#0d131f',
          border: '2px solid #1e293b',
          borderRadius: 8,
          boxShadow: '3px 3px 0px #020408'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: '0.68rem', fontFamily: 'JetBrains Mono, monospace', color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>
              ACTIVE SUBNET
            </span>
            <span style={{
              width: 8, height: 8, borderRadius: '50%', background: '#10b981',
              display: 'inline-block', boxShadow: '0 0 8px #10b981'
            }} className="pulse-dot" />
          </div>
          <div style={{ fontSize: '0.85rem', fontFamily: 'JetBrains Mono, monospace', color: '#06b6d4', fontWeight: 700 }}>
            {activeNetworkInfo.subnet || '192.168.1.0/24'}
          </div>
        </div>

        {/* Nav Links */}
        <nav style={{ flex: 1, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 6 }}>
          <p style={{
            fontSize: '0.68rem', fontFamily: 'JetBrains Mono, monospace',
            color: '#475569', fontWeight: 700, textTransform: 'uppercase',
            letterSpacing: '0.08em', padding: '6px 4px 2px'
          }}>
            SYSTEM MODULES
          </p>

          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            const Icon = item.icon;

            return (
              <NavLink
                key={item.name}
                to={item.path}
                end={item.path === '/'}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '10px 12px',
                  borderRadius: 8,
                  border: isActive ? '2px solid #06b6d4' : '2px solid transparent',
                  background: isActive ? '#111726' : 'transparent',
                  boxShadow: isActive ? '3px 3px 0px #06b6d4' : 'none',
                  color: isActive ? '#f8fafc' : '#94a3b8',
                  fontWeight: isActive ? 700 : 600,
                  fontSize: '0.875rem',
                  textDecoration: 'none',
                  transition: 'all 0.1s ease',
                  position: 'relative'
                }}
                onMouseEnter={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.background = '#0e1524';
                    e.currentTarget.style.color = '#e2e8f0';
                    e.currentTarget.style.borderColor = '#1e293b';
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isActive) {
                    e.currentTarget.style.background = 'transparent';
                    e.currentTarget.style.color = '#94a3b8';
                    e.currentTarget.style.borderColor = 'transparent';
                  }
                }}
              >
                <Icon size={18} color={isActive ? '#06b6d4' : '#64748b'} />
                <span style={{ flex: 1 }}>{item.name}</span>

                {item.badge && (
                  <span style={{
                    padding: '2px 7px',
                    borderRadius: 5,
                    fontSize: '0.68rem',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontWeight: 700,
                    background: item.badgeColor || '#06b6d4',
                    color: item.badgeColor === '#06b6d4' ? '#041017' : '#ffffff',
                    border: '1.5px solid #000',
                    boxShadow: '1.5px 1.5px 0px #000'
                  }}>
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* User & Sign Out Footer */}
        <div style={{
          padding: '14px',
          borderTop: '2.5px solid #1e293b',
          background: '#090d16',
          display: 'flex',
          flexDirection: 'column',
          gap: 10
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 28, height: 28, borderRadius: 6,
                background: '#1e293b', border: '1.5px solid #334155',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontFamily: 'JetBrains Mono, monospace', fontSize: '0.78rem', fontWeight: 700, color: '#38bdf8'
              }}>
                {user?.username ? user.username[0].toUpperCase() : 'A'}
              </div>
              <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#cbd5e1' }}>
                {user?.username || 'Analyst'}
              </span>
            </div>
            <span style={{
              fontSize: '0.65rem',
              fontFamily: 'JetBrains Mono, monospace',
              color: '#10b981',
              background: 'rgba(16,185,129,0.1)',
              padding: '2px 6px',
              borderRadius: 4,
              border: '1px solid #10b981'
            }}>
              ONLINE
            </span>
          </div>

          <button
            onClick={handleLogout}
            className="neo-btn neo-btn-ghost"
            style={{ width: '100%', padding: '7px 12px', fontSize: '0.78rem' }}
          >
            <LogOut size={14} />
            Sign Out
          </button>
        </div>
      </aside>

      {/* ── Main View Area ── */}
      <main style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        position: 'relative',
        background: '#070a11'
      }}>
        {/* Cyber Grid Background Texture */}
        <div style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: `
            linear-gradient(to right, rgba(30, 41, 59, 0.25) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(30, 41, 59, 0.25) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
          pointerEvents: 'none',
          opacity: 0.7
        }} />

        <div style={{ flex: 1, overflowY: 'auto', padding: '24px 30px', position: 'relative', zIndex: 1 }}>
          <Outlet />
        </div>
      </main>

      {user?.must_change_password && (
        <ChangePasswordModal
          username={user.username}
          onDone={() => setUser({ ...user, must_change_password: false })}
        />
      )}
    </div>
  );
}

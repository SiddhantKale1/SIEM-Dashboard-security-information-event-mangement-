import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { Shield, LayoutDashboard, Server, FileText, LogOut } from 'lucide-react';

export default function MainLayout() {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/login');
  };

  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Devices', path: '/devices', icon: Server },
    { name: 'Logs', path: '/logs', icon: FileText },
  ];

  return (
    <div className="flex h-screen bg-[var(--color-dark-bg)] overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 border-r border-[var(--color-dark-border)] bg-[var(--color-dark-surface)]/50 flex flex-col">
        <div className="h-16 flex items-center px-6 border-b border-[var(--color-dark-border)]">
          <Shield className="w-6 h-6 text-brand-primary mr-3" />
          <span className="text-lg font-bold text-white tracking-wide">SIEM<span className="text-brand-primary">MVP</span></span>
        </div>
        
        <nav className="flex-1 py-6 px-4 space-y-2">
          {navItems.map((item) => (
            <NavLink
              key={item.name}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center px-4 py-3 rounded-lg transition-all duration-200 group ${
                  isActive
                    ? 'bg-brand-primary/10 text-brand-primary font-medium'
                    : 'text-gray-400 hover:bg-[#2a2e39] hover:text-gray-100'
                }`
              }
            >
              <item.icon className="w-5 h-5 mr-3" />
              {item.name}
            </NavLink>
          ))}
        </nav>
        
        <div className="p-4 border-t border-[var(--color-dark-border)]">
          <button
            onClick={handleLogout}
            className="flex items-center w-full px-4 py-3 text-gray-400 hover:bg-[#2a2e39] hover:text-red-400 rounded-lg transition-colors"
          >
            <LogOut className="w-5 h-5 mr-3" />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col relative overflow-hidden">
        {/* Glow decoration */}
        <div className="absolute top-0 right-0 w-[40%] h-[30%] rounded-full bg-brand-primary/5 blur-[120px] pointer-events-none" />
        
        <div className="flex-1 overflow-y-auto p-8 relative z-10">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

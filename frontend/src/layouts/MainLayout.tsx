import { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { 
  LayoutGrid, 
  Monitor, 
  ShieldAlert, 
  Radio, 
  Terminal, 
  ChevronLeft, 
  ChevronRight, 
  BookOpen, 
  Headphones, 
  ShieldCheck, 
  Search, 
  Bell, 
  Settings as SettingsIcon, 
  Plus
} from 'lucide-react';
import api from '../services/api';

export default function MainLayout() {
  const navigate = useNavigate();
  const [user, setUser] = useState<{ username: string } | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeThreats, setActiveThreats] = useState<number>(0);

  useEffect(() => {
    api.get('/auth/me')
      .then(res => setUser(res.data))
      .catch(() => {
        setUser({ username: 'Admin' });
      });

    api.get('/anomalies/stats')
      .then(res => setActiveThreats(res.data?.active_threats || 0))
      .catch(() => {});
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/login');
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#f4f5f7] text-[#111827] font-sans antialiased">
      
      {/* ── Left Sidebar ── */}
      <aside 
        className={`bg-white border-r border-[#eaecf0] flex flex-col justify-between transition-all duration-300 z-30 shrink-0 ${
          sidebarCollapsed ? 'w-20' : 'w-[230px]'
        }`}
      >
        <div className="flex flex-col flex-1 overflow-y-auto px-4 py-5">
          {/* Brand Header */}
          <div className="flex items-center justify-between mb-8 px-2">
            {!sidebarCollapsed ? (
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-xl bg-[#111827] flex items-center justify-center text-white shadow-xs">
                  <ShieldCheck className="w-4 h-4 text-[#82c341]" />
                </div>
                <div className="flex flex-col">
                  <span className="text-lg font-black tracking-tight text-[#111827] leading-none">
                    SENTINEL
                  </span>
                  <span className="text-[10px] font-bold text-[#82c341] tracking-wider mt-0.5">
                    SIEM PLATFORM
                  </span>
                </div>
              </div>
            ) : (
              <div className="w-8 h-8 rounded-xl bg-[#111827] flex items-center justify-center text-white mx-auto shadow-xs">
                <ShieldCheck className="w-4 h-4 text-[#82c341]" />
              </div>
            )}
          </div>

          {/* Navigation Links */}
          <nav className="flex flex-col gap-1.5">
            {/* Dashboard */}
            <NavLink
              to="/"
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-semibold transition-all relative ${
                  isActive
                    ? 'bg-[#f4f5f7] text-[#111827]'
                    : 'text-[#6b7280] hover:text-[#111827] hover:bg-[#f9fafb]'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {isActive && (
                    <span className="absolute left-0 top-2 bottom-2 w-1 bg-[#111827] rounded-r-full" />
                  )}
                  <LayoutGrid className="w-4 h-4 shrink-0 text-[#111827]" />
                  {!sidebarCollapsed && <span>Dashboard</span>}
                </>
              )}
            </NavLink>

            {/* Endpoints */}
            <NavLink
              to="/endpoints"
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-[#f4f5f7] text-[#111827] font-semibold'
                    : 'text-[#6b7280] hover:text-[#111827] hover:bg-[#f9fafb]'
                }`
              }
            >
              <Monitor className="w-4 h-4 shrink-0 text-[#6b7280]" />
              {!sidebarCollapsed && <span>Endpoints</span>}
            </NavLink>

            {/* Security Logs */}
            <NavLink
              to="/logs"
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-[#f4f5f7] text-[#111827] font-semibold'
                    : 'text-[#6b7280] hover:text-[#111827] hover:bg-[#f9fafb]'
                }`
              }
            >
              <Terminal className="w-4 h-4 shrink-0 text-[#6b7280]" />
              {!sidebarCollapsed && <span>Security Logs</span>}
            </NavLink>

            {/* Network Flow */}
            <NavLink
              to="/network"
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-[#f4f5f7] text-[#111827] font-semibold'
                    : 'text-[#6b7280] hover:text-[#111827] hover:bg-[#f9fafb]'
                }`
              }
            >
              <Radio className="w-4 h-4 shrink-0 text-[#6b7280]" />
              {!sidebarCollapsed && <span>Network Flow</span>}
            </NavLink>

            {/* AI Threat Radar */}
            <NavLink
              to="/threats"
              className={({ isActive }) =>
                `flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-[#f4f5f7] text-[#111827] font-semibold'
                    : 'text-[#6b7280] hover:text-[#111827] hover:bg-[#f9fafb]'
                }`
              }
            >
              <div className="flex items-center gap-3">
                <ShieldAlert className="w-4 h-4 shrink-0 text-[#6b7280]" />
                {!sidebarCollapsed && <span>AI Threat Radar</span>}
              </div>
              {!sidebarCollapsed && activeThreats > 0 && (
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-[#fee2e2] text-[#991b1b]">
                  {activeThreats}
                </span>
              )}
            </NavLink>

            {/* Spacing / Section */}
            <div className="my-3 border-t border-[#f0f2f5]" />

            {/* Documentation */}
            <a
              href="https://github.com/SiddhantKale1/SIEM-Dashboard-security-information-event-mangement-"
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium text-[#6b7280] hover:text-[#111827] hover:bg-[#f9fafb] transition-all"
            >
              <BookOpen className="w-4 h-4 shrink-0 text-[#6b7280]" />
              {!sidebarCollapsed && <span>Documentation</span>}
            </a>

            {/* API Support */}
            <a
              href="http://localhost:8000/docs"
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium text-[#6b7280] hover:text-[#111827] hover:bg-[#f9fafb] transition-all"
            >
              <Headphones className="w-4 h-4 shrink-0 text-[#6b7280]" />
              {!sidebarCollapsed && <span>API Swagger</span>}
            </a>
          </nav>
        </div>

        {/* Bottom Section */}
        <div className="p-3 flex flex-col gap-2 border-t border-[#eaecf0]">
          {/* Collapse sidebar toggle */}
          <button
            type="button"
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="flex items-center gap-2 px-2 py-2 text-xs font-semibold text-[#6b7280] hover:text-[#111827] transition-colors"
          >
            {sidebarCollapsed ? (
              <ChevronRight className="w-4 h-4 mx-auto" />
            ) : (
              <>
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>Collapse sidebar</span>
              </>
            )}
          </button>
        </div>
      </aside>

      {/* ── Main Content Container ── */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        
        {/* ── Top Header ── */}
        <header className="h-16 px-6 bg-transparent flex items-center justify-between shrink-0">
          {/* Search bar */}
          <div className="relative w-84">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[#9ca3af]" />
            <input
              type="text"
              placeholder="Search security logs, hosts, IPs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-white border border-[#e5e7eb] rounded-xl pl-10 pr-4 py-2 text-xs font-medium text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#82c341] transition-all shadow-2xs"
            />
          </div>

          {/* Right Header Cluster */}
          <div className="flex items-center gap-3">
            
            {/* Notification Bell */}
            <button
              type="button"
              onClick={() => navigate('/threats')}
              title={`${activeThreats} active threats`}
              className="relative w-9 h-9 rounded-xl bg-white border border-[#e5e7eb] flex items-center justify-center text-[#4b5563] hover:text-[#111827] hover:border-[#d1d5db] transition-all shadow-2xs"
            >
              <Bell className="w-4 h-4" />
              {activeThreats > 0 ? (
                <span className="absolute top-2 right-2 w-2 h-2 bg-[#ef4444] rounded-full ring-2 ring-white" />
              ) : (
                <span className="absolute top-2 right-2 w-1.5 h-1.5 bg-[#82c341] rounded-full ring-2 ring-white" />
              )}
            </button>

            {/* Settings */}
            <button
              type="button"
              onClick={handleLogout}
              title="Click to Logout"
              className="w-9 h-9 rounded-xl bg-white border border-[#e5e7eb] flex items-center justify-center text-[#4b5563] hover:text-[#111827] hover:border-[#d1d5db] transition-all shadow-2xs"
            >
              <SettingsIcon className="w-4 h-4" />
            </button>

            {/* Operator Profile Pill */}
            <div className="flex items-center gap-2.5 bg-white border border-[#e5e7eb] pl-1.5 pr-4 py-1 rounded-full shadow-2xs cursor-pointer hover:border-[#d1d5db] transition-all">
              <div className="w-7 h-7 rounded-full bg-[#111827] text-white text-xs font-bold flex items-center justify-center">
                {user?.username?.substring(0, 2).toUpperCase() || 'AD'}
              </div>
              <div className="flex flex-col text-left leading-none">
                <span className="text-xs font-bold text-[#111827]">
                  {user?.username || 'admin'}
                </span>
                <span className="text-[10px] text-[#9ca3af] mt-0.5">
                  admin@siem.local
                </span>
              </div>
            </div>

            {/* Enroll Device Button */}
            <button
              type="button"
              onClick={() => navigate('/endpoints')}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-[#111827] text-white rounded-xl text-xs font-semibold hover:bg-black transition-all shadow-2xs"
            >
              <Plus className="w-3.5 h-3.5 text-[#82c341]" />
              <span>Enroll Device</span>
            </button>
          </div>
        </header>

        {/* ── Main Body Workspace ── */}
        <main className="flex-1 overflow-y-auto px-6 pb-6 pt-1">
          <Outlet />
        </main>
      </div>

    </div>
  );
}

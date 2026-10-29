import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { 
  Copy, 
  Check, 
  Plus, 
  Trash2, 
  Lock, 
  Unlock, 
  ShieldCheck,
  Monitor,
  Terminal,
  ArrowRight,
  RefreshCw,
  Search
} from 'lucide-react';
import api from '../services/api';
import { copyToClipboard } from '../utils/clipboard';
import { WindowsIcon, LinuxPenguinIcon } from '../components/OSIcons';

export default function Endpoints({ defaultTab }: { defaultTab?: 'view_devices' | 'installers' } = {}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [devices, setDevices] = useState<any[]>([]);
  const [tokens, setTokens] = useState<any[]>([]);
  const [activeInstallCommands, setActiveInstallCommands] = useState<{ linux: string; windows: string } | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [generatingToken, setGeneratingToken] = useState(false);
  const [activeTab, setActiveTab] = useState<'view_devices' | 'installers'>(() => {
    if (defaultTab) return defaultTab;
    return 'view_devices';
  });
  const [searchQuery, setSearchQuery] = useState('');
  const [customServerUrl, setCustomServerUrl] = useState('');

  const getEffectiveCmd = (cmd: string) => {
    if (!customServerUrl.trim()) return cmd;
    const target = customServerUrl.trim().replace(/\/$/, '');
    return cmd
      .replace(/https?:\/\/[a-zA-Z0-9.\-_:]+(?=\/api|\?server|$)/g, target)
      .replace(/server=https?:\/\/[a-zA-Z0-9.\-_:]+/g, `server=${target}`)
      .replace(/--server "https?:\/\/[a-zA-Z0-9.\-_:]+"/g, `--server "${target}"`);
  };

  useEffect(() => {
    if (defaultTab) {
      setActiveTab(defaultTab);
    }
  }, [defaultTab, location.pathname]);

  const loadData = async () => {
    try {
      const [devRes, tokRes] = await Promise.all([
        api.get('/network/active'),
        api.get('/enrollment/tokens')
      ]);
      setDevices(devRes.data?.devices || []);
      setTokens(tokRes.data || []);
    } catch (e) {
      console.error("Failed to load endpoint data:", e);
    }
  };

  const handleGeneratePermanentToken = async () => {
    setGeneratingToken(true);
    try {
      const res = await api.post('/enrollment/token?reusable=true&days_valid=90');
      setActiveInstallCommands(res.data.install_commands);
      loadData();
    } catch (err: any) {
      console.error("Failed to generate permanent token:", err);
    } finally {
      setGeneratingToken(false);
    }
  };

  const handleCopyCmd = async (cmd: string, key: string) => {
    const ok = await copyToClipboard(cmd);
    if (ok) {
      setCopiedCmd(key);
      setTimeout(() => setCopiedCmd(null), 2500);
    }
  };

  const handleIsolate = async (deviceId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await api.post(`/devices/${deviceId}/isolate`);
      loadData();
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Isolation failed");
    }
  };

  const handleRestore = async (deviceId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await api.post(`/devices/${deviceId}/restore`);
      loadData();
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Restore failed");
    }
  };

  const handleDeleteDevice = async (dev: any, e: React.MouseEvent) => {
    e.stopPropagation();
    const id = dev.device_id || dev._id;
    if (!id) return;
    if (!window.confirm(`Delete device "${dev.hostname || id}" from SIEM fleet?`)) return;

    try {
      await api.delete(`/devices/${id}`);
      loadData();
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Failed to delete device");
    }
  };

  const handleRevokeToken = async (tokenId: string) => {
    if (!window.confirm("Revoke this token? Existing agents will remain authenticated, but no new computers can use it.")) return;
    try {
      await api.delete(`/enrollment/tokens/${tokenId}`);
      loadData();
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Revocation failed");
    }
  };

  useEffect(() => {
    loadData();
    handleGeneratePermanentToken();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const filteredDevices = devices.filter((d: any) => {
    const q = searchQuery.toLowerCase();
    return (
      (d.hostname || '').toLowerCase().includes(q) ||
      (d.ip_address || '').toLowerCase().includes(q) ||
      (d.device_id || '').toLowerCase().includes(q) ||
      (d.os || '').toLowerCase().includes(q)
    );
  });

  return (
    <div className="flex flex-col gap-5 max-w-[1600px] mx-auto pb-8 font-sans">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-extrabold text-[#111827] tracking-tight">
              Enrolled Endpoint Fleet
            </h1>
            <span className="text-xs font-bold px-2.5 py-0.5 rounded-full bg-[#dcfce7] text-[#166534]">
              {devices.length} CONNECTED
            </span>
          </div>
          <p className="text-xs text-[#6b7280] mt-1 font-medium">
            Monitor real-time system logs, network socket traffic, and active telemetry from enrolled endpoints
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button 
            type="button"
            onClick={loadData}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#e5e7eb] rounded-xl text-xs font-semibold text-[#111827] hover:bg-[#f9fafb] transition-all shadow-2xs"
          >
            <RefreshCw className="w-3.5 h-3.5 text-[#6b7280]" />
            <span>Refresh Fleet</span>
          </button>

          <button 
            type="button"
            onClick={() => setActiveTab(activeTab === 'view_devices' ? 'installers' : 'view_devices')}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-[#111827] text-white rounded-xl text-xs font-semibold hover:bg-black transition-all shadow-2xs"
          >
            {activeTab === 'view_devices' ? <Terminal className="w-3.5 h-3.5 text-[#82c341]" /> : <Monitor className="w-3.5 h-3.5 text-[#82c341]" />}
            <span>{activeTab === 'view_devices' ? 'Install on New PC' : 'View Enrolled Devices'}</span>
          </button>
        </div>
      </div>

      {/* View Switcher Tabs */}
      <div className="flex gap-2 border-b border-[#e5e7eb] pb-3">
        <button
          type="button"
          onClick={() => setActiveTab('view_devices')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'view_devices' 
              ? 'bg-[#111827] text-white shadow-2xs' 
              : 'bg-white border border-[#e5e7eb] text-[#6b7280] hover:text-[#111827]'
          }`}
        >
          <Monitor className="w-3.5 h-3.5" />
          <span>View Enrolled Devices ({devices.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('installers')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'installers' 
              ? 'bg-[#111827] text-white shadow-2xs' 
              : 'bg-white border border-[#e5e7eb] text-[#6b7280] hover:text-[#111827]'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>1-Click Installers (Linux &amp; Windows)</span>
        </button>
      </div>

      {/* ── OPTION 1: VIEW ENROLLED DEVICES ── */}
      {activeTab === 'view_devices' && (
        <div className="flex flex-col gap-5">
          
          {/* Search Bar */}
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="relative w-80">
              <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[#9ca3af]" />
              <input
                type="text"
                placeholder="Search by hostname, IP, OS..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full bg-white border border-[#e5e7eb] rounded-xl pl-10 pr-4 py-2 text-xs font-medium text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#82c341] transition-all shadow-2xs"
              />
            </div>
          </div>

          {/* Connected Device Cards Grid */}
          {filteredDevices.length === 0 ? (
            <div className="bg-white rounded-[24px] p-10 border border-[#f0f2f5] text-center shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
              <Monitor className="w-10 h-10 text-[#9ca3af] mx-auto mb-3" />
              <h3 className="text-base font-extrabold text-[#111827] mb-1">No Connected Devices Found</h3>
              <p className="text-xs text-[#6b7280] max-w-md mx-auto mb-4">
                Run the one-time installer command on any Windows or Linux computer on your network to enroll it.
              </p>
              <button 
                type="button"
                onClick={() => setActiveTab('installers')}
                className="px-4 py-2 bg-[#111827] text-white text-xs font-bold rounded-xl hover:bg-black transition-all"
              >
                Get Installer Commands →
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {filteredDevices.map((dev: any) => {
                const isWin = (dev.os || '').toLowerCase().includes('win');
                const isLin = (dev.os || '').toLowerCase().includes('linux') || (dev.os || '').toLowerCase().includes('ubuntu');
                const isOnline = dev.current_network_state === 'online' || dev.status === 'online';
                const isIsolated = dev.status === 'isolated';

                return (
                  <div
                    key={dev._id || dev.device_id}
                    onClick={() => dev.device_id && navigate(`/devices/${dev.device_id}`)}
                    className={`bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex flex-col justify-between cursor-pointer hover:border-[#82c341] transition-all ${
                      isIsolated ? 'border-[#fecaca]' : ''
                    }`}
                  >
                    {/* Top Row: Device Name & Status */}
                    <div className="flex items-start justify-between gap-3 mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-11 h-11 rounded-2xl bg-[#f4f5f7] border border-[#e5e7eb] flex items-center justify-center shrink-0">
                          {isWin ? <WindowsIcon /> : isLin ? <LinuxPenguinIcon /> : <Monitor className="w-5 h-5 text-[#6b7280]" />}
                        </div>
                        <div>
                          <h4 className="text-sm font-extrabold text-[#111827] tracking-tight">
                            {dev.hostname || 'Unknown Host'}
                          </h4>
                          <span className="text-[11px] font-mono text-[#9ca3af]">
                            {dev.device_id || 'Unmanaged'}
                          </span>
                        </div>
                      </div>

                      <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full uppercase ${
                        isIsolated ? 'bg-[#fee2e2] text-[#991b1b]' : isOnline ? 'bg-[#dcfce7] text-[#166534]' : 'bg-[#f3f4f6] text-[#4b5563]'
                      }`}>
                        {isIsolated ? 'ISOLATED' : isOnline ? 'ONLINE' : 'OFFLINE'}
                      </span>
                    </div>

                    {/* Middle: Details Grid */}
                    <div className="bg-[#f9fafb] border border-[#f0f2f5] rounded-xl p-3 grid grid-cols-2 gap-2 text-xs font-mono mb-4">
                      <div>
                        <span className="text-[10px] text-[#9ca3af] block">IP ADDRESS</span>
                        <span className="font-bold text-[#111827]">{dev.ip_address}</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-[#9ca3af] block">OS PLATFORM</span>
                        <span className="font-bold text-[#111827]">
                          {isWin ? 'Windows' : isLin ? 'Linux' : dev.os || 'Unknown'}
                        </span>
                      </div>
                      <div>
                        <span className="text-[10px] text-[#9ca3af] block">SUBNET</span>
                        <span className="text-[#4b5563]">{dev.subnet || '—'}</span>
                      </div>
                      <div>
                        <span className="text-[10px] text-[#9ca3af] block">MAC ADDRESS</span>
                        <span className="text-[#4b5563] truncate block">{dev.mac_address || '—'}</span>
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center justify-between pt-2 border-t border-[#f4f5f7]">
                      <div className="flex items-center gap-2">
                        {isIsolated ? (
                          <button
                            type="button"
                            onClick={(e) => handleRestore(dev.device_id, e)}
                            className="px-2.5 py-1.5 bg-[#dcfce7] text-[#166534] rounded-lg text-xs font-bold hover:bg-[#bbf7d0] transition-colors flex items-center gap-1"
                          >
                            <Unlock className="w-3 h-3" />
                            <span>Restore</span>
                          </button>
                        ) : dev.device_id ? (
                          <button
                            type="button"
                            onClick={(e) => handleIsolate(dev.device_id, e)}
                            className="px-2.5 py-1.5 bg-[#fee2e2] text-[#991b1b] rounded-lg text-xs font-bold hover:bg-[#fecaca] transition-colors flex items-center gap-1"
                          >
                            <Lock className="w-3 h-3" />
                            <span>Isolate</span>
                          </button>
                        ) : null}

                        <button
                          type="button"
                          onClick={(e) => handleDeleteDevice(dev, e)}
                          className="p-1.5 text-[#ef4444] hover:bg-[#fee2e2] rounded-lg transition-colors"
                          title="Delete endpoint"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>

                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (dev.device_id) navigate(`/devices/${dev.device_id}`);
                        }}
                        className="text-xs font-bold text-[#111827] hover:text-[#82c341] flex items-center gap-1 transition-colors"
                      >
                        <span>Telemetry</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Full Table Roster View */}
          <div className="bg-white rounded-[24px] p-6 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
            <h3 className="text-sm font-extrabold text-[#111827] mb-3">
              Enrolled Endpoint Roster Table ({devices.length} systems)
            </h3>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#e5e7eb] text-[#6b7280] font-mono text-[11px]">
                    <th className="py-2.5 px-3">DEVICE</th>
                    <th className="py-2.5 px-3">OS</th>
                    <th className="py-2.5 px-3">STATUS</th>
                    <th className="py-2.5 px-3">IP ADDRESS</th>
                    <th className="py-2.5 px-3">DEVICE ID</th>
                    <th className="py-2.5 px-3 text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#f0f2f5]">
                  {filteredDevices.map((dev: any) => {
                    const isWin = (dev.os || '').toLowerCase().includes('win');
                    const isLin = (dev.os || '').toLowerCase().includes('linux') || (dev.os || '').toLowerCase().includes('ubuntu');
                    return (
                      <tr
                        key={dev._id || dev.device_id}
                        onClick={() => dev.device_id && navigate(`/devices/${dev.device_id}`)}
                        className="hover:bg-[#f9fafb] cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-3 font-bold text-[#111827] flex items-center gap-2">
                          <Monitor className="w-4 h-4 text-[#82c341]" />
                          <span>{dev.hostname || 'Unknown Endpoint'}</span>
                        </td>
                        <td className="py-3 px-3">
                          <span className="font-semibold text-[#374151]">
                            {isWin ? 'Windows' : isLin ? 'Linux' : dev.os || 'Unknown'}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                            dev.status === 'isolated' ? 'bg-[#fee2e2] text-[#991b1b]' : 'bg-[#dcfce7] text-[#166534]'
                          }`}>
                            {dev.status === 'isolated' ? 'ISOLATED' : 'ONLINE'}
                          </span>
                        </td>
                        <td className="py-3 px-3 font-mono text-[#4b5563]">
                          {dev.ip_address}
                        </td>
                        <td className="py-3 px-3 font-mono text-[11px] text-[#9ca3af]">
                          {dev.device_id || 'N/A'}
                        </td>
                        <td className="py-3 px-3 text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (dev.device_id) navigate(`/devices/${dev.device_id}`);
                            }}
                            className="px-3 py-1 bg-white border border-[#e5e7eb] rounded-lg text-xs font-semibold text-[#111827] hover:bg-[#f9fafb]"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── OPTION 2: 1-CLICK INSTALLERS ── */}
      {activeTab === 'installers' && (
        <div className="flex flex-col gap-5">
          <div className="bg-white rounded-[24px] p-6 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
            <div className="flex items-center gap-2 mb-2">
              <ShieldCheck className="w-5 h-5 text-[#82c341]" />
              <h2 className="text-base font-extrabold text-[#111827]">
                Permanent Endpoint Deployment (Survives Reboots &amp; Background)
              </h2>
            </div>
            <p className="text-xs text-[#6b7280] leading-relaxed max-w-3xl mb-5">
              Execute this command once in an Administrator (PowerShell) or sudo (Linux) terminal. 
              The agent sets up a systemd service or startup task and detaches into the background automatically.
            </p>

            {activeInstallCommands ? (
              <div className="flex flex-col gap-4">
                {/* Host Override Bar */}
                <div className="bg-[#f9fafb] border border-[#e5e7eb] rounded-2xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
                  <div className="flex-1 w-full">
                    <label className="text-[11px] font-bold text-[#374151] block mb-1 uppercase tracking-wider">
                      Server Endpoint Host / Public Tunnel URL
                    </label>
                    <input
                      type="text"
                      placeholder="Leave blank for local LAN (or paste public tunnel URL)"
                      value={customServerUrl}
                      onChange={(e) => setCustomServerUrl(e.target.value)}
                      className="w-full bg-white border border-[#d1d5db] rounded-lg px-3 py-1.5 text-xs font-mono text-[#111827] focus:outline-none focus:border-[#82c341]"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={() => setCustomServerUrl('https://peoples-susan-scholar-reggae.trycloudflare.com')}
                    className="mt-1 md:mt-4 px-3 py-1.5 bg-[#f0fdf4] text-[#166534] border border-[#bbf7d0] rounded-lg text-xs font-bold hover:bg-[#dcfce7] transition-colors whitespace-nowrap"
                  >
                    ⚡ Use Live Tunnel (Remote Devices)
                  </button>
                  {customServerUrl && (
                    <button
                      type="button"
                      onClick={() => setCustomServerUrl('')}
                      className="mt-1 md:mt-4 px-2.5 py-1.5 bg-white text-[#6b7280] border border-[#e5e7eb] rounded-lg text-xs font-semibold hover:bg-[#f3f4f6]"
                    >
                      Reset to LAN
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  {/* Linux Installer */}
                  <div className="bg-[#f9fafb] border border-[#e5e7eb] rounded-2xl p-4 flex flex-col justify-between">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-bold text-[#111827] flex items-center gap-1.5 font-mono">
                        <LinuxPenguinIcon /> LINUX DAEMON (SYSTEMD)
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopyCmd(getEffectiveCmd(activeInstallCommands.linux), 'linux')}
                        className="px-2.5 py-1 bg-white border border-[#e5e7eb] rounded-lg text-xs font-semibold text-[#111827] flex items-center gap-1 hover:bg-[#f3f4f6]"
                      >
                        {copiedCmd === 'linux' ? <Check className="w-3.5 h-3.5 text-[#82c341]" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedCmd === 'linux' ? 'Copied!' : 'Copy'}</span>
                      </button>
                    </div>
                    <pre className="bg-white border border-[#e5e7eb] rounded-xl p-3 text-[11px] font-mono text-[#111827] overflow-x-auto whitespace-pre-wrap break-all">
                      {getEffectiveCmd(activeInstallCommands.linux)}
                    </pre>
                  </div>

                  {/* Windows Installer */}
                  <div className="bg-[#f9fafb] border border-[#e5e7eb] rounded-2xl p-4 flex flex-col justify-between">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-bold text-[#111827] flex items-center gap-1.5 font-mono">
                        <WindowsIcon /> WINDOWS TASK (POWERSHELL)
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopyCmd(getEffectiveCmd(activeInstallCommands.windows), 'windows')}
                        className="px-2.5 py-1 bg-white border border-[#e5e7eb] rounded-lg text-xs font-semibold text-[#111827] flex items-center gap-1 hover:bg-[#f3f4f6]"
                      >
                        {copiedCmd === 'windows' ? <Check className="w-3.5 h-3.5 text-[#82c341]" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedCmd === 'windows' ? 'Copied!' : 'Copy'}</span>
                      </button>
                    </div>
                    <pre className="bg-white border border-[#e5e7eb] rounded-xl p-3 text-[11px] font-mono text-[#111827] overflow-x-auto whitespace-pre-wrap break-all">
                      {getEffectiveCmd(activeInstallCommands.windows)}
                    </pre>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-6 text-xs text-[#9ca3af]">
                Generating active fleet installation tokens...
              </div>
            )}
          </div>

          {/* Tokens Panel */}
          {tokens.length > 0 && (
            <div className="bg-white rounded-[24px] p-6 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-sm font-extrabold text-[#111827]">
                  Active Fleet Enrollment Tokens ({tokens.length})
                </h4>
                <button
                  type="button"
                  onClick={handleGeneratePermanentToken}
                  disabled={generatingToken}
                  className="px-3 py-1.5 bg-[#111827] text-white rounded-xl text-xs font-semibold flex items-center gap-1 hover:bg-black"
                >
                  <Plus className="w-3.5 h-3.5 text-[#82c341]" />
                  <span>Generate New Token</span>
                </button>
              </div>

              <div className="flex flex-col gap-2">
                {tokens.map((tok: any) => (
                  <div
                    key={tok.id}
                    className="flex items-center justify-between bg-[#f9fafb] border border-[#e5e7eb] rounded-xl px-4 py-2.5 text-xs font-mono"
                  >
                    <div className="flex items-center gap-4">
                      <span className="font-bold text-[#111827]">{tok.token_preview}</span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-white border border-[#e5e7eb] text-[#374151]">
                        {tok.reusable ? 'REUSABLE FLEET KEY' : 'SINGLE USE'}
                      </span>
                      <span className="text-[#6b7280]">Used {tok.use_count} times</span>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleRevokeToken(tok.id)}
                      className="text-[#ef4444] hover:bg-[#fee2e2] p-1.5 rounded-lg transition-colors"
                      title="Revoke Token"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

    </div>
  );
}

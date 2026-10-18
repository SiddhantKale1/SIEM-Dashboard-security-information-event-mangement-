import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
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

export default function Endpoints() {
  const navigate = useNavigate();
  const [devices, setDevices] = useState<any[]>([]);
  const [tokens, setTokens] = useState<any[]>([]);
  const [activeInstallCommands, setActiveInstallCommands] = useState<{ linux: string; windows: string } | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [generatingToken, setGeneratingToken] = useState(false);
  const [activeTab, setActiveTab] = useState<'view_devices' | 'installers'>('view_devices');
  const [searchQuery, setSearchQuery] = useState('');

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
      alert(err?.response?.data?.detail || "Failed to generate permanent token");
    } finally {
      setGeneratingToken(false);
    }
  };

  const handleRevokeToken = async (id: string) => {
    try {
      await api.delete(`/enrollment/tokens/${id}`);
      loadData();
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Failed to revoke token");
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

  const handleDeleteDevice = async (device: any, e: React.MouseEvent) => {
    e.stopPropagation();
    const id = device.device_id || device._id;
    const name = device.hostname || id;
    if (!window.confirm(`Permanently remove endpoint "${name}" from monitoring?\n\nAll associated logs, telemetry, processes, anomalies, and connection history will be deleted.`)) return;
    try {
      await api.delete(`/devices/${id}`);
      loadData();
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Failed to delete endpoint");
    }
  };

  const handleCopyCmd = async (text: string, label: string) => {
    const success = await copyToClipboard(text);
    if (success) {
      setCopiedCmd(label);
      setTimeout(() => setCopiedCmd(null), 2500);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 8000);
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, margin: 0, letterSpacing: '-0.03em', color: '#f8fafc' }}>
              Enrolled Endpoint Fleet
            </h1>
            <span className="neo-badge neo-badge-emerald">
              {devices.length} CONNECTED
            </span>
          </div>
          <p style={{ margin: '4px 0 0', fontSize: '0.85rem', color: '#64748b' }}>
            Monitor real-time system logs, network socket traffic, and active telemetry from enrolled endpoints
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button 
            onClick={() => setActiveTab(activeTab === 'view_devices' ? 'installers' : 'view_devices')}
            className="neo-btn neo-btn-cyan"
            style={{ padding: '8px 16px', fontSize: '0.82rem' }}
          >
            {activeTab === 'view_devices' ? <Terminal size={15} /> : <Monitor size={15} />}
            {activeTab === 'view_devices' ? 'Install on New PC' : 'View Enrolled Devices'}
          </button>
        </div>
      </div>

      {/* View Switcher Tabs */}
      <div style={{ display: 'flex', gap: 10, borderBottom: '2px solid #161e30', paddingBottom: 10 }}>
        <button
          onClick={() => setActiveTab('view_devices')}
          className={`neo-btn ${activeTab === 'view_devices' ? 'neo-btn-cyan' : ''}`}
          style={{ padding: '8px 16px', fontSize: '0.82rem', background: activeTab !== 'view_devices' ? '#0a0f1b' : undefined }}
        >
          <Monitor size={15} /> View Enrolled Devices ({devices.length})
        </button>

        <button
          onClick={() => setActiveTab('installers')}
          className={`neo-btn ${activeTab === 'installers' ? 'neo-btn-violet' : ''}`}
          style={{ padding: '8px 16px', fontSize: '0.82rem', background: activeTab !== 'installers' ? '#0a0f1b' : undefined }}
        >
          <Terminal size={15} /> 1-Click Installers (Linux &amp; Windows)
        </button>
      </div>

      {/* ── OPTION 1: VIEW ENROLLED DEVICES (CARDS & DETAIL ROSTER) ── */}
      {activeTab === 'view_devices' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          
          {/* Search Bar */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
            <div style={{ position: 'relative', width: 300 }}>
              <Search size={14} color="#64748b" style={{ position: 'absolute', left: 12, top: 11 }} />
              <input
                type="text"
                placeholder="Search by hostname, IP, OS..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="neo-input"
                style={{ paddingLeft: 34, fontSize: '0.82rem', height: 36 }}
              />
            </div>

            <button 
              onClick={loadData} 
              className="neo-btn" 
              style={{ padding: '6px 12px', fontSize: '0.78rem', background: '#0a0f1b' }}
            >
              <RefreshCw size={13} /> Refresh Fleet
            </button>
          </div>

          {/* Connected Device Bento Grid */}
          {filteredDevices.length === 0 ? (
            <div className="bento-card" style={{ padding: 40, textAlign: 'center' }}>
              <Monitor size={36} color="#475569" style={{ margin: '0 auto 12px' }} />
              <h3 style={{ color: '#f8fafc', margin: '0 0 6px', fontSize: '1.1rem' }}>No Connected Devices Found</h3>
              <p style={{ color: '#64748b', fontSize: '0.82rem', maxWidth: 460, margin: '0 auto 16px' }}>
                Run the one-time installer command on any Windows or Linux computer on your network to enroll it.
              </p>
              <button 
                onClick={() => setActiveTab('installers')}
                className="neo-btn neo-btn-cyan"
                style={{ padding: '8px 16px', fontSize: '0.82rem' }}
              >
                Get Installer Commands →
              </button>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 16 }}>
              {filteredDevices.map((dev: any) => {
                const isWin = (dev.os || '').toLowerCase().includes('win');
                const isLin = (dev.os || '').toLowerCase().includes('linux') || (dev.os || '').toLowerCase().includes('ubuntu');
                const isOnline = dev.current_network_state === 'online' || dev.status === 'online';
                const isIsolated = dev.status === 'isolated';

                return (
                  <div
                    key={dev._id || dev.device_id}
                    onClick={() => dev.device_id && navigate(`/devices/${dev.device_id}`)}
                    className="bento-card"
                    style={{
                      padding: 20, cursor: 'pointer',
                      border: `2px solid ${isIsolated ? '#f43f5e' : isOnline ? '#10b981' : '#1e293b'}`,
                      background: '#0a0f1b',
                      transition: 'transform 0.15s, border-color 0.15s',
                      display: 'flex', flexDirection: 'column', gap: 14
                    }}
                    onMouseEnter={e => e.currentTarget.style.transform = 'translateY(-2px)'}
                    onMouseLeave={e => e.currentTarget.style.transform = 'translateY(0)'}
                  >
                    {/* Top Row: Computer Icon + OS Logo + Status */}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        {/* Computer Icon with OS badge */}
                        <div style={{
                          width: 44, height: 44, borderRadius: 8,
                          background: '#070a11', border: '1.5px solid #1e293b',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          position: 'relative'
                        }}>
                          <Monitor size={22} color="#06b6d4" />
                          <div style={{
                            position: 'absolute', bottom: -4, right: -4,
                            background: '#070a11', borderRadius: '50%', padding: 2,
                            border: '1px solid #1e293b'
                          }}>
                            {isWin ? <WindowsIcon size={14} /> : isLin ? <LinuxPenguinIcon size={15} /> : null}
                          </div>
                        </div>

                        <div>
                          {/* Device Name */}
                          <div style={{ fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em' }}>
                            {dev.hostname || 'Unknown Endpoint'}
                          </div>
                          <div style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>
                            {dev.device_id || 'Unmanaged'}
                          </div>
                        </div>
                      </div>

                      {/* Status Badge */}
                      <span className={`neo-badge neo-badge-${isIsolated ? 'isolated' : isOnline ? 'online' : 'offline'}`}>
                        {isIsolated ? 'ISOLATED' : isOnline ? 'ONLINE' : 'OFFLINE'}
                      </span>
                    </div>

                    {/* Middle: Details */}
                    <div style={{
                      background: '#070a11', border: '1px solid #161e30', borderRadius: 6,
                      padding: '10px 12px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8,
                      fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace'
                    }}>
                      <div>
                        <span style={{ color: '#64748b' }}>IP ADDRESS:</span>
                        <div style={{ color: '#06b6d4', fontWeight: 700 }}>{dev.ip_address}</div>
                      </div>
                      <div>
                        <span style={{ color: '#64748b' }}>OS PLATFORM:</span>
                        <div style={{ color: isWin ? '#38bdf8' : isLin ? '#fbbf24' : '#cbd5e1', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4 }}>
                          {isWin ? <WindowsIcon size={12} /> : isLin ? <LinuxPenguinIcon size={13} /> : null}
                          {isWin ? 'Windows' : isLin ? 'Linux' : dev.os || 'Unknown'}
                        </div>
                      </div>
                      <div>
                        <span style={{ color: '#64748b' }}>SUBNET:</span>
                        <div style={{ color: '#cbd5e1' }}>{dev.subnet || '—'}</div>
                      </div>
                      <div>
                        <span style={{ color: '#64748b' }}>MAC:</span>
                        <div style={{ color: '#8b5cf6' }}>{dev.mac_address || '—'}</div>
                      </div>
                    </div>

                    {/* Bottom: Action Trigger to inspect system & network logs */}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 4 }}>
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        {isIsolated ? (
                          <button
                            onClick={(e) => handleRestore(dev.device_id, e)}
                            className="neo-btn neo-btn-emerald"
                            style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                          >
                            <Unlock size={11} /> Restore
                          </button>
                        ) : dev.device_id ? (
                          <button
                            onClick={(e) => handleIsolate(dev.device_id, e)}
                            className="neo-btn neo-btn-coral"
                            style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                          >
                            <Lock size={11} /> Isolate
                          </button>
                        ) : null}

                        <button
                          onClick={(e) => handleDeleteDevice(dev, e)}
                          className="neo-btn"
                          style={{
                            padding: '4px 8px',
                            fontSize: '0.72rem',
                            background: 'rgba(239, 68, 68, 0.1)',
                            border: '1px solid rgba(239, 68, 68, 0.3)',
                            color: '#f87171'
                          }}
                          title="Delete system from monitoring"
                        >
                          <Trash2 size={11} />
                        </button>
                      </div>

                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (dev.device_id) navigate(`/devices/${dev.device_id}`);
                        }}
                        className="neo-btn neo-btn-cyan"
                        style={{ padding: '6px 14px', fontSize: '0.75rem', fontWeight: 800 }}
                      >
                        Inspect Logs &amp; Telemetry <ArrowRight size={13} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Full Table View */}
          <div className="bento-card" style={{ padding: 22 }}>
            <h3 style={{ margin: '0 0 14px', fontSize: '1rem', fontWeight: 800, color: '#f8fafc' }}>
              Enrolled Endpoint Roster Table ({devices.length} systems)
            </h3>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
                <thead>
                  <tr style={{ borderBottom: '2.5px solid #1e293b', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem' }}>
                    <th style={{ padding: '10px 12px' }}>DEVICE</th>
                    <th style={{ padding: '10px 12px' }}>OS</th>
                    <th style={{ padding: '10px 12px' }}>STATUS</th>
                    <th style={{ padding: '10px 12px' }}>IP ADDRESS</th>
                    <th style={{ padding: '10px 12px' }}>DEVICE ID</th>
                    <th style={{ padding: '10px 12px' }}>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDevices.map((dev: any) => {
                    const isWin = (dev.os || '').toLowerCase().includes('win');
                    const isLin = (dev.os || '').toLowerCase().includes('linux') || (dev.os || '').toLowerCase().includes('ubuntu');
                    return (
                      <tr
                        key={dev._id || dev.device_id}
                        onClick={() => dev.device_id && navigate(`/devices/${dev.device_id}`)}
                        style={{ borderBottom: '1px solid #161e30', cursor: 'pointer', transition: 'background 0.1s' }}
                        onMouseEnter={e => e.currentTarget.style.background = '#0e1524'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                      >
                        <td style={{ padding: '12px', fontWeight: 800, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 8 }}>
                          <Monitor size={16} color="#06b6d4" />
                          <span>{dev.hostname || 'Unknown Endpoint'}</span>
                        </td>
                        <td style={{ padding: '12px' }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 700, color: isWin ? '#38bdf8' : isLin ? '#fbbf24' : '#cbd5e1' }}>
                            {isWin ? <WindowsIcon size={14} /> : isLin ? <LinuxPenguinIcon size={16} /> : null}
                            {isWin ? 'Windows' : isLin ? 'Linux' : dev.os || 'Unknown'}
                          </span>
                        </td>
                        <td style={{ padding: '12px' }}>
                          <span className={`neo-badge neo-badge-${dev.status === 'isolated' ? 'isolated' : dev.current_network_state === 'online' ? 'online' : 'offline'}`}>
                            {dev.status === 'isolated' ? 'ISOLATED' : dev.current_network_state || 'ONLINE'}
                          </span>
                        </td>
                        <td style={{ padding: '12px', fontFamily: 'JetBrains Mono, monospace', color: '#06b6d4' }}>
                          {dev.ip_address}
                        </td>
                        <td style={{ padding: '12px', fontFamily: 'JetBrains Mono, monospace', color: '#8b5cf6', fontSize: '0.78rem' }}>
                          {dev.device_id || 'N/A'}
                        </td>
                        <td style={{ padding: '12px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                if (dev.device_id) navigate(`/devices/${dev.device_id}`);
                              }}
                              className="neo-btn neo-btn-cyan"
                              style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                            >
                              View Logs &amp; Traffic →
                            </button>
                            <button
                              onClick={(e) => handleDeleteDevice(dev, e)}
                              className="neo-btn"
                              style={{
                                padding: '4px 8px',
                                fontSize: '0.72rem',
                                background: 'rgba(239, 68, 68, 0.1)',
                                border: '1px solid rgba(239, 68, 68, 0.3)',
                                color: '#f87171'
                              }}
                              title="Delete endpoint from monitoring system"
                            >
                              <Trash2 size={12} />
                            </button>
                          </div>
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

      {/* ── OPTION 2: INSTALLERS (BOOT PERSISTENT FLEET SETUP) ── */}
      {activeTab === 'installers' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div className="bento-card bento-card-cyan" style={{ padding: 24, background: '#0a0f1b' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <ShieldCheck size={20} color="#06b6d4" />
              <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc', margin: 0 }}>
                Permanent Endpoint Setup (Survives Reboots &amp; Terminal Closes)
              </h2>
            </div>
            <p style={{ fontSize: '0.84rem', color: '#94a3b8', margin: '0 0 18px', maxWidth: 840, lineHeight: 1.5 }}>
              Run the command below once in Administrator / sudo terminal. The installer writes a permanent local credential, 
              registers a <strong>systemd service on Linux</strong> or a <strong>startup task on Windows</strong>, and immediately detaches into the background. 
              You can safely close PowerShell/terminal. Whenever the PC boots, it resumes sending telemetry and logs automatically.
            </p>

            {activeInstallCommands ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 16 }}>
                {/* Linux One-Liner */}
                <div style={{
                  background: '#070a11', border: '2px solid #1e293b',
                  borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', gap: 10
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.78rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, color: '#fbbf24', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <LinuxPenguinIcon size={18} /> LINUX (SYSTEMD BACKGROUND SERVICE)
                    </span>
                    <button
                      onClick={() => handleCopyCmd(activeInstallCommands.linux, 'linux')}
                      className="neo-btn neo-btn-cyan"
                      style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                    >
                      {copiedCmd === 'linux' ? <Check size={13} /> : <Copy size={13} />}
                      {copiedCmd === 'linux' ? 'Copied!' : 'Copy Command'}
                    </button>
                  </div>

                  <div style={{
                    background: '#04070d', border: '1px solid #151d2e', borderRadius: 6,
                    padding: '10px 12px', fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '0.75rem', color: '#38bdf8', overflowX: 'auto', whiteSpace: 'nowrap'
                  }}>
                    {activeInstallCommands.linux}
                  </div>
                </div>

                {/* Windows One-Liner */}
                <div style={{
                  background: '#070a11', border: '2px solid #1e293b',
                  borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', gap: 10
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.78rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <WindowsIcon size={16} /> WINDOWS (PERSISTENT BOOT TASK)
                    </span>
                    <button
                      onClick={() => handleCopyCmd(activeInstallCommands.windows, 'windows')}
                      className="neo-btn neo-btn-violet"
                      style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                    >
                      {copiedCmd === 'windows' ? <Check size={13} /> : <Copy size={13} />}
                      {copiedCmd === 'windows' ? 'Copied!' : 'Copy Command'}
                    </button>
                  </div>

                  <div style={{
                    background: '#04070d', border: '1px solid #151d2e', borderRadius: 6,
                    padding: '10px 12px', fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '0.75rem', color: '#c084fc', overflowX: 'auto', whiteSpace: 'nowrap'
                  }}>
                    {activeInstallCommands.windows}
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ padding: 20, textAlign: 'center', color: '#64748b' }}>
                Generating active deployment commands...
              </div>
            )}
          </div>

          {/* Active Fleet Tokens Panel */}
          {tokens.length > 0 && (
            <div className="bento-card" style={{ padding: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 800, color: '#f8fafc' }}>
                  Active Enrollment Keys ({tokens.length})
                </h4>
                <button
                  onClick={handleGeneratePermanentToken}
                  disabled={generatingToken}
                  className="neo-btn neo-btn-cyan"
                  style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                >
                  <Plus size={12} /> New Key
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {tokens.map((tok: any) => (
                  <div
                    key={tok.id}
                    style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      background: '#070a11', border: '1px solid #161e30', borderRadius: 6,
                      padding: '8px 12px', fontSize: '0.78rem', fontFamily: 'JetBrains Mono, monospace'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <span style={{ color: '#06b6d4', fontWeight: 700 }}>{tok.token_preview}</span>
                      <span className="neo-badge neo-badge-cyan" style={{ fontSize: '0.65rem' }}>
                        {tok.reusable ? 'REUSABLE FLEET KEY' : 'SINGLE USE'}
                      </span>
                      <span style={{ color: '#64748b' }}>Used {tok.use_count} times</span>
                    </div>

                    <button
                      onClick={() => handleRevokeToken(tok.id)}
                      className="neo-btn neo-btn-coral"
                      style={{ padding: '3px 8px', fontSize: '0.7rem' }}
                      title="Revoke Token"
                    >
                      <Trash2 size={12} />
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

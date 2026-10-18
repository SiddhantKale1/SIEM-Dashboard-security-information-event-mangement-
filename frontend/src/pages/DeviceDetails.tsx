import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../services/api';
import { 
  ArrowLeft, 
  ShieldAlert, 
  ShieldCheck, 
  Cpu, 
  HardDrive, 
  Activity, 
  Terminal, 
  Radio, 
  Monitor, 
  RefreshCw, 
  Search, 
  Layers,
  Globe,
  ExternalLink
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { WindowsIcon, LinuxPenguinIcon } from '../components/OSIcons';

const EVENT_STYLES: Record<string, { color: string; bg: string; dot: string }> = {
  enrolled:  { color: '#10b981', bg: 'rgba(16,185,129,0.08)', dot: '#10b981' },
  isolated:  { color: '#f43f5e', bg: 'rgba(244,63,94,0.08)',  dot: '#f43f5e' },
  restored:  { color: '#06b6d4', bg: 'rgba(6,182,212,0.08)',  dot: '#06b6d4' },
  connected: { color: '#8b5cf6', bg: 'rgba(139,92,246,0.08)', dot: '#8b5cf6' },
};

export default function DeviceDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [device, setDevice] = useState<any>(null);
  const [metrics, setMetrics] = useState<any[]>([]);
  const [systemLogs, setSystemLogs] = useState<any[]>([]);
  const [networkData, setNetworkData] = useState<any>({ sessions: [], network_logs: [], visited_domains: [], bandwidth_metrics: [], anomalies: [] });
  const [processes, setProcesses] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [actioning, setActioning] = useState(false);
  const [activeTab, setActiveTab] = useState<'system_logs' | 'network_logs' | 'telemetry' | 'timeline'>('system_logs');
  const [logFilter, setLogFilter] = useState('');
  const [logSeverity, setLogSeverity] = useState('all');
  const [netTabFilter, setNetTabFilter] = useState<'all' | 'websites' | 'sockets'>('all');
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  const showToast = (msg: string, type: 'success' | 'error' = 'success') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const loadAllDeviceData = async () => {
    if (!id) return;
    try {
      const [devRes, metRes, sysLogRes, netRes, procRes, evtRes] = await Promise.all([
        api.get(`/devices/${id}`),
        api.get(`/devices/${id}/metrics`).catch(() => ({ data: [] })),
        api.get(`/devices/${id}/system-logs`).catch(() => ({ data: [] })),
        api.get(`/devices/${id}/network-logs`).catch(() => ({ data: { sessions: [], network_logs: [], bandwidth_metrics: [], anomalies: [] } })),
        api.get(`/devices/${id}/processes`).catch(() => ({ data: { processes: [] } })),
        api.get(`/devices/${id}/events`).catch(() => ({ data: [] }))
      ]);

      setDevice(devRes.data);
      setMetrics(Array.isArray(metRes.data) ? metRes.data : []);
      setSystemLogs(Array.isArray(sysLogRes.data) ? sysLogRes.data : []);
      setNetworkData(netRes.data || { sessions: [], network_logs: [], bandwidth_metrics: [], anomalies: [] });
      setProcesses(procRes.data?.processes || []);
      setEvents(Array.isArray(evtRes.data) ? evtRes.data : []);
    } catch (err: any) {
      console.error("Failed to load device details:", err);
      showToast("Could not load endpoint telemetry.", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllDeviceData();
    const interval = setInterval(loadAllDeviceData, 10000); // 10s live polling
    return () => clearInterval(interval);
  }, [id]);

  const handleIsolate = async () => {
    if (!window.confirm(`Quarantine & isolate endpoint "${device?.hostname}"? This immediately blocks traffic and revokes agent keys.`)) return;
    setActioning(true);
    try {
      await api.post(`/devices/${id}/isolate`);
      showToast(`Quarantine initiated: ${device?.hostname} isolated.`);
      await loadAllDeviceData();
    } catch (err: any) {
      showToast(err?.response?.data?.detail || 'Isolation failed.', 'error');
    } finally { 
      setActioning(false); 
    }
  };

  const handleRestore = async () => {
    if (!window.confirm(`Restore network access for "${device?.hostname}"?`)) return;
    setActioning(true);
    try {
      await api.post(`/devices/${id}/restore`);
      showToast(`Access restored for ${device?.hostname}.`);
      await loadAllDeviceData();
    } catch (err: any) {
      showToast(err?.response?.data?.detail || 'Restore failed.', 'error');
    } finally { 
      setActioning(false); 
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 300, gap: 12 }}>
        <RefreshCw size={24} className="animate-spin" color="#06b6d4" />
        <span style={{ fontSize: '0.85rem', color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>
          Connecting to endpoint telemetry stream...
        </span>
      </div>
    );
  }

  if (!device) {
    return (
      <div className="bento-card" style={{ padding: 40, textAlign: 'center' }}>
        <h2 style={{ color: '#f43f5e', margin: '0 0 10px' }}>Endpoint Not Found</h2>
        <p style={{ color: '#64748b', fontSize: '0.85rem' }}>No enrolled endpoint registered with ID: {id}</p>
        <button onClick={() => navigate('/endpoints')} className="neo-btn neo-btn-cyan" style={{ marginTop: 15 }}>
          Back to Enrolled Fleet
        </button>
      </div>
    );
  }

  const isWindows = (device.os || '').toLowerCase().includes('win');
  const isLinux = (device.os || '').toLowerCase().includes('linux') || (device.os || '').toLowerCase().includes('ubuntu');
  const latestMetric = metrics.length ? metrics[metrics.length - 1] : null;

  // Filtered system logs
  const filteredSystemLogs = systemLogs.filter((log: any) => {
    const matchesSev = logSeverity === 'all' || (log.severity || '').toLowerCase() === logSeverity.toLowerCase();
    const text = `${log.message || ''} ${log.source || ''} ${log.event_id || ''}`.toLowerCase();
    const matchesQuery = !logFilter || text.includes(logFilter.toLowerCase());
    return matchesSev && matchesQuery;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Toast Notification */}
      {toast && (
        <div style={{
          position: 'fixed', top: 24, right: 24, zIndex: 9999,
          background: toast.type === 'success' ? '#0f291e' : '#2d1217',
          border: `2px solid ${toast.type === 'success' ? '#10b981' : '#f43f5e'}`,
          color: toast.type === 'success' ? '#10b981' : '#f43f5e',
          padding: '12px 20px', borderRadius: 8, fontSize: '0.85rem', fontWeight: 700,
          boxShadow: '4px 4px 0px #020408',
          fontFamily: 'JetBrains Mono, monospace'
        }}>
          {toast.msg}
        </div>
      )}

      {/* Top Header Card */}
      <div className="bento-card" style={{ padding: 22 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <button
              onClick={() => navigate('/endpoints')}
              className="neo-btn"
              style={{ width: 38, height: 38, padding: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0a0f1b' }}
              title="Back to Fleet"
            >
              <ArrowLeft size={16} />
            </button>

            {/* Computer Icon + OS Badge */}
            <div style={{
              width: 50, height: 50, borderRadius: 10,
              background: '#070a11', border: '2px solid #1e293b',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              position: 'relative'
            }}>
              <Monitor size={26} color="#06b6d4" />
              <div style={{ position: 'absolute', bottom: -4, right: -4, background: '#070a11', borderRadius: '50%', padding: 2, border: '1px solid #1e293b' }}>
                {isWindows ? <WindowsIcon size={16} /> : isLinux ? <LinuxPenguinIcon size={16} /> : null}
              </div>
            </div>

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h1 style={{ fontSize: '1.5rem', fontWeight: 800, margin: 0, color: '#f8fafc', letterSpacing: '-0.02em' }}>
                  {device.hostname || 'Unknown Endpoint'}
                </h1>
                
                {/* OS Tag with Penguin / Windows Icon */}
                <div style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  background: isWindows ? 'rgba(56,189,248,0.12)' : 'rgba(251,191,36,0.12)',
                  border: `1.5px solid ${isWindows ? '#38bdf8' : '#fbbf24'}`,
                  borderRadius: 6, padding: '3px 8px', fontSize: '0.72rem', fontWeight: 800,
                  fontFamily: 'JetBrains Mono, monospace', color: isWindows ? '#38bdf8' : '#fbbf24'
                }}>
                  {isWindows ? <WindowsIcon size={14} /> : <LinuxPenguinIcon size={16} />}
                  <span>{isWindows ? 'WINDOWS SYSTEM' : 'LINUX SYSTEM'}</span>
                </div>

                <span className={`neo-badge neo-badge-${device.status === 'isolated' ? 'isolated' : device.status === 'online' ? 'online' : 'offline'}`}>
                  {device.status ? device.status.toUpperCase() : 'OFFLINE'}
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 4, fontSize: '0.78rem', color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>
                <span>IP: <strong style={{ color: '#06b6d4' }}>{device.ip_address || 'N/A'}</strong></span>
                <span>•</span>
                <span>MAC: <strong style={{ color: '#8b5cf6' }}>{device.mac_address || 'N/A'}</strong></span>
                <span>•</span>
                <span>Subnet: <strong style={{ color: '#f8fafc' }}>{device.subnet || '192.168.1.0/24'}</strong></span>
                <span>•</span>
                <span>Agent: <strong style={{ color: '#10b981' }}>v{device.agent_version || '2.0.0'}</strong></span>
              </div>
            </div>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: 10 }}>
            <button 
              onClick={loadAllDeviceData}
              className="neo-btn" 
              style={{ padding: '8px 14px', fontSize: '0.78rem', background: '#0a0f1b' }}
              title="Refresh Telemetry"
            >
              <RefreshCw size={14} /> Refresh
            </button>

            {device.status === 'online' && (
              <button 
                onClick={handleIsolate} 
                disabled={actioning}
                className="neo-btn neo-btn-coral"
                style={{ padding: '8px 16px', fontSize: '0.78rem' }}
              >
                <ShieldAlert size={14} /> {actioning ? 'Isolating...' : '1-Click Quarantine'}
              </button>
            )}

            {device.status === 'isolated' && (
              <button 
                onClick={handleRestore} 
                disabled={actioning}
                className="neo-btn neo-btn-emerald"
                style={{ padding: '8px 16px', fontSize: '0.78rem' }}
              >
                <ShieldCheck size={14} /> {actioning ? 'Restoring...' : 'Restore Network Access'}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: 10, borderBottom: '2px solid #161e30', paddingBottom: 10 }}>
        <button
          onClick={() => setActiveTab('system_logs')}
          className={`neo-btn ${activeTab === 'system_logs' ? 'neo-btn-cyan' : ''}`}
          style={{ padding: '8px 16px', fontSize: '0.8rem', background: activeTab !== 'system_logs' ? '#0a0f1b' : undefined }}
        >
          <Terminal size={14} /> System Logs ({systemLogs.length})
        </button>

        <button
          onClick={() => setActiveTab('network_logs')}
          className={`neo-btn ${activeTab === 'network_logs' ? 'neo-btn-violet' : ''}`}
          style={{ padding: '8px 16px', fontSize: '0.8rem', background: activeTab !== 'network_logs' ? '#0a0f1b' : undefined }}
        >
          <Radio size={14} /> Network Logs &amp; Activity ({networkData.network_logs?.length || 0})
        </button>

        <button
          onClick={() => setActiveTab('telemetry')}
          className={`neo-btn ${activeTab === 'telemetry' ? 'neo-btn-emerald' : ''}`}
          style={{ padding: '8px 16px', fontSize: '0.8rem', background: activeTab !== 'telemetry' ? '#0a0f1b' : undefined }}
        >
          <Activity size={14} /> Live Telemetry &amp; Processes ({processes.length})
        </button>

        <button
          onClick={() => setActiveTab('timeline')}
          className={`neo-btn ${activeTab === 'timeline' ? 'neo-btn-cyan' : ''}`}
          style={{ padding: '8px 16px', fontSize: '0.8rem', background: activeTab !== 'timeline' ? '#0a0f1b' : undefined }}
        >
          <Layers size={14} /> Audit Timeline ({events.length})
        </button>
      </div>

      {/* ── TAB 1: SYSTEM LOGS ── */}
      {activeTab === 'system_logs' && (
        <div className="bento-card" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, marginBottom: 16 }}>
            <div>
              <h3 style={{ margin: '0 0 4px', fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
                Real-Time System Log Stream ({filteredSystemLogs.length} events)
              </h3>
              <p style={{ margin: 0, fontSize: '0.78rem', color: '#64748b' }}>
                Actual OS security &amp; system journals streamed live from {device.hostname}
              </p>
            </div>

            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <div style={{ position: 'relative', width: 220 }}>
                <Search size={14} color="#64748b" style={{ position: 'absolute', left: 10, top: 10 }} />
                <input
                  type="text"
                  placeholder="Filter logs..."
                  value={logFilter}
                  onChange={e => setLogFilter(e.target.value)}
                  className="neo-input"
                  style={{ paddingLeft: 32, fontSize: '0.78rem', height: 34 }}
                />
              </div>

              <select
                value={logSeverity}
                onChange={e => setLogSeverity(e.target.value)}
                className="neo-input"
                style={{ height: 34, fontSize: '0.78rem', padding: '0 10px', width: 120 }}
              >
                <option value="all">All Severities</option>
                <option value="error">Error</option>
                <option value="warning">Warning</option>
                <option value="information">Info</option>
              </select>
            </div>
          </div>

          {filteredSystemLogs.length === 0 ? (
            <div style={{ padding: '40px 20px', textAlign: 'center', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.82rem' }}>
              {systemLogs.length === 0 
                ? "No system logs streamed yet. Waiting for endpoint agent dispatch cycle (sent every 10s)..." 
                : "No logs matched the current filter."}
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
                <thead>
                  <tr style={{ borderBottom: '2px solid #1e293b', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}>
                    <th style={{ padding: '10px 12px' }}>SEVERITY</th>
                    <th style={{ padding: '10px 12px' }}>TIMESTAMP</th>
                    <th style={{ padding: '10px 12px' }}>SOURCE</th>
                    <th style={{ padding: '10px 12px' }}>EVENT ID</th>
                    <th style={{ padding: '10px 12px' }}>MESSAGE</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSystemLogs.map((l: any, i: number) => {
                    const sev = (l.severity || 'info').toLowerCase();
                    const badgeColor = sev === 'error' ? '#f43f5e' : sev === 'warning' ? '#f59e0b' : '#38bdf8';
                    return (
                      <tr 
                        key={l._id || i}
                        style={{ borderBottom: '1px solid #161e30', fontFamily: 'JetBrains Mono, monospace' }}
                      >
                        <td style={{ padding: '10px 12px' }}>
                          <span style={{
                            display: 'inline-block', padding: '2px 6px', borderRadius: 4,
                            fontSize: '0.68rem', fontWeight: 800, textTransform: 'uppercase',
                            background: `${badgeColor}18`, color: badgeColor, border: `1px solid ${badgeColor}40`
                          }}>
                            {sev}
                          </span>
                        </td>
                        <td style={{ padding: '10px 12px', color: '#64748b', whiteSpace: 'nowrap', fontSize: '0.75rem' }}>
                          {l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : '—'}
                        </td>
                        <td style={{ padding: '10px 12px', color: '#8b5cf6', fontWeight: 700 }}>
                          {l.source || l.source_type || 'system'}
                        </td>
                        <td style={{ padding: '10px 12px', color: '#cbd5e1' }}>
                          {l.event_id || 'LOG'}
                        </td>
                        <td style={{ padding: '10px 12px', color: '#f8fafc', wordBreak: 'break-word', maxWidth: 500 }}>
                          {l.message || 'No log details'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── TAB 2: NETWORK LOGS & ACTIVITY ── */}
      {activeTab === 'network_logs' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Subnet & Network Sessions Card */}
          <div className="bento-card bento-card-violet" style={{ padding: 22 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
              <Radio size={18} color="#8b5cf6" />
              <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
                Active &amp; Historical Network Sessions ({networkData.sessions?.length || 0})
              </h3>
            </div>

            {(!networkData.sessions || networkData.sessions.length === 0) ? (
              <p style={{ color: '#64748b', fontSize: '0.82rem', fontFamily: 'JetBrains Mono, monospace' }}>
                No connection sessions logged for this device yet.
              </p>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #1e293b', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}>
                      <th style={{ padding: '8px 12px' }}>STATUS</th>
                      <th style={{ padding: '8px 12px' }}>SUBNET</th>
                      <th style={{ padding: '8px 12px' }}>IP ASSIGNED</th>
                      <th style={{ padding: '8px 12px' }}>CONNECTED AT</th>
                      <th style={{ padding: '8px 12px' }}>DURATION</th>
                      <th style={{ padding: '8px 12px' }}>TERMINATION REASON</th>
                    </tr>
                  </thead>
                  <tbody>
                    {networkData.sessions.map((sess: any) => (
                      <tr key={sess._id} style={{ borderBottom: '1px solid #161e30', fontFamily: 'JetBrains Mono, monospace' }}>
                        <td style={{ padding: '8px 12px' }}>
                          <span className={`neo-badge neo-badge-${sess.status === 'active' ? 'online' : 'offline'}`}>
                            {sess.status.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ padding: '8px 12px', color: '#06b6d4', fontWeight: 700 }}>
                          {sess.subnet}
                        </td>
                        <td style={{ padding: '8px 12px', color: '#f8fafc' }}>
                          {sess.ip_address}
                        </td>
                        <td style={{ padding: '8px 12px', color: '#64748b' }}>
                          {sess.connected_at ? new Date(sess.connected_at).toLocaleString() : '—'}
                        </td>
                        <td style={{ padding: '8px 12px', color: '#10b981' }}>
                          {sess.duration_seconds ? `${sess.duration_seconds}s` : 'Active Now'}
                        </td>
                        <td style={{ padding: '8px 12px', color: '#64748b' }}>
                          {sess.termination_reason || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Visited Websites & Web Domains Bento Card — Always Visible */}
          <div className="bento-card bento-card-cyan" style={{ padding: 22 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Globe size={18} color="#00f0ff" />
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
                    Visited Websites &amp; Queried Domains ({networkData.visited_domains?.length || 0})
                  </h3>
                  <p style={{ margin: '2px 0 0', fontSize: '0.75rem', color: '#94a3b8' }}>
                    Real website queries captured live from {device?.hostname || 'endpoint'}'s operating system DNS resolver cache
                  </p>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="neo-badge neo-badge-online" style={{ fontSize: '0.7rem', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span className="pulse-dot" style={{ width: 7, height: 7, borderRadius: '50%', background: '#00ff66' }} />
                  REAL OS DNS LISTENER
                </span>
              </div>
            </div>

            {networkData.visited_domains && networkData.visited_domains.length > 0 ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 12 }}>
                {networkData.visited_domains.map((vd: any, idx: number) => (
                  <div 
                    key={idx} 
                    style={{ 
                      padding: '12px 14px', 
                      background: 'rgba(15, 23, 42, 0.75)', 
                      borderRadius: 8, 
                      border: '2px solid rgba(0, 240, 255, 0.3)',
                      boxShadow: '3px 3px 0px #000',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 6
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ color: '#00f0ff', fontWeight: 800, fontSize: '0.85rem', fontFamily: 'JetBrains Mono, monospace', display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Globe size={13} color="#00f0ff" />
                        {vd.domain}
                      </span>
                      <a 
                        href={`https://${vd.domain}`} 
                        target="_blank" 
                        rel="noreferrer" 
                        style={{ color: '#94a3b8', transition: 'color 0.2s' }}
                        title={`Open https://${vd.domain}`}
                      >
                        <ExternalLink size={13} />
                      </a>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'JetBrains Mono, monospace' }}>
                      <span>IP: <strong style={{ color: '#cbd5e1' }}>{vd.resolved_ip || '—'}</strong></span>
                      <span>{vd.timestamp ? new Date(vd.timestamp).toLocaleTimeString() : 'Recent'}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{
                padding: '24px 20px',
                background: 'rgba(11, 16, 26, 0.8)',
                border: '1.5px dashed rgba(0, 240, 255, 0.35)',
                borderRadius: 8,
                textAlign: 'center',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 10
              }}>
                <div style={{
                  width: 44,
                  height: 44,
                  borderRadius: '50%',
                  background: 'rgba(0, 240, 255, 0.1)',
                  border: '1.5px solid #00f0ff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#00f0ff'
                }}>
                  <Globe size={22} />
                </div>
                <div>
                  <h4 style={{ margin: '0 0 4px', fontSize: '0.92rem', fontWeight: 700, color: '#f8fafc' }}>
                    Active DNS &amp; Web Traffic Listener Ready
                  </h4>
                  <p style={{ margin: 0, fontSize: '0.78rem', color: '#94a3b8', maxWidth: 560, lineHeight: 1.5 }}>
                    The universal endpoint agent is actively monitoring the operating system DNS cache and outbound browser sockets on <strong>{device?.hostname || 'this device'}</strong> ({device?.ip_address || 'local'}). As websites are accessed, they will appear here in real time.
                  </p>
                </div>
                <div style={{
                  marginTop: 6,
                  padding: '6px 14px',
                  borderRadius: 6,
                  background: 'rgba(255, 230, 0, 0.1)',
                  border: '1px solid rgba(255, 230, 0, 0.3)',
                  fontSize: '0.74rem',
                  fontFamily: 'JetBrains Mono, monospace',
                  color: '#ffe600'
                }}>
                  👉 Open <strong>youtube.com</strong> or any website in Chrome / Edge / Firefox on {device?.hostname || 'the endpoint'} to see it appear!
                </div>
              </div>
            )}
          </div>

          {/* Real Network Socket & Flow Logs */}
          <div className="bento-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Terminal size={18} color="#00f0ff" />
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
                    Network Traffic &amp; Visited Websites Stream ({(networkData.network_logs || []).filter((nl: any) => {
                      const isWeb = nl.event_id === 'DNS_QUERY' || nl.event_id === 'WEB_VISIT' || nl.source === 'dns_cache' || nl.source === 'browser_network' || (nl.message && nl.message.includes('🌐'));
                      if (netTabFilter === 'websites') return isWeb;
                      if (netTabFilter === 'sockets') return !isWeb;
                      return true;
                    }).length})
                  </h3>
                  <p style={{ margin: '2px 0 0', fontSize: '0.75rem', color: '#94a3b8' }}>
                    Live website visits (DNS), socket connections, and listeners streamed from {device?.hostname || 'endpoint'}
                  </p>
                </div>
              </div>

              {/* Filter Pills */}
              <div style={{ display: 'flex', gap: 6, background: '#090d16', padding: 4, borderRadius: 8, border: '1px solid #1e293b' }}>
                <button
                  type="button"
                  onClick={() => setNetTabFilter('all')}
                  style={{
                    padding: '4px 10px',
                    borderRadius: 6,
                    fontSize: '0.72rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                    border: 'none',
                    background: netTabFilter === 'all' ? '#1e293b' : 'transparent',
                    color: netTabFilter === 'all' ? '#f8fafc' : '#64748b',
                    transition: 'all 0.15s'
                  }}
                >
                  All ({(networkData.network_logs || []).length})
                </button>
                <button
                  type="button"
                  onClick={() => setNetTabFilter('websites')}
                  style={{
                    padding: '4px 10px',
                    borderRadius: 6,
                    fontSize: '0.72rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                    border: 'none',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 5,
                    background: netTabFilter === 'websites' ? 'rgba(6, 182, 212, 0.2)' : 'transparent',
                    color: netTabFilter === 'websites' ? '#06b6d4' : '#64748b',
                    transition: 'all 0.15s'
                  }}
                >
                  <Globe size={11} />
                  Websites ({(networkData.network_logs || []).filter((nl: any) => nl.event_id === 'DNS_QUERY' || nl.source === 'dns_cache' || (nl.message && nl.message.includes('🌐'))).length})
                </button>
                <button
                  type="button"
                  onClick={() => setNetTabFilter('sockets')}
                  style={{
                    padding: '4px 10px',
                    borderRadius: 6,
                    fontSize: '0.72rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                    border: 'none',
                    background: netTabFilter === 'sockets' ? 'rgba(139, 92, 246, 0.2)' : 'transparent',
                    color: netTabFilter === 'sockets' ? '#8b5cf6' : '#64748b',
                    transition: 'all 0.15s'
                  }}
                >
                  Sockets ({(networkData.network_logs || []).filter((nl: any) => !(nl.event_id === 'DNS_QUERY' || nl.source === 'dns_cache' || (nl.message && nl.message.includes('🌐')))).length})
                </button>
              </div>
            </div>

            {(!networkData.network_logs || networkData.network_logs.length === 0) ? (
              <div style={{ padding: '30px 10px', textAlign: 'center', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.82rem' }}>
                No network socket events captured yet. The agent streams active network sockets &amp; DNS queries every 10s.
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #1e293b', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}>
                      <th style={{ padding: '8px 12px' }}>TIME</th>
                      <th style={{ padding: '8px 12px' }}>SOURCE</th>
                      <th style={{ padding: '8px 12px' }}>EVENT TYPE</th>
                      <th style={{ padding: '8px 12px' }}>DETAILS &amp; DESTINATION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(networkData.network_logs || [])
                      .filter((nl: any) => {
                        const isWeb = nl.event_id === 'DNS_QUERY' || nl.source === 'dns_cache' || (nl.message && nl.message.includes('🌐'));
                        if (netTabFilter === 'websites') return isWeb;
                        if (netTabFilter === 'sockets') return !isWeb;
                        return true;
                      })
                      .map((nl: any, i: number) => {
                        const isDns = nl.event_id === 'DNS_QUERY' || nl.source === 'dns_cache' || (nl.message && nl.message.includes('🌐'));
                        return (
                          <tr key={nl._id || i} style={{ borderBottom: '1px solid #161e30', fontFamily: 'JetBrains Mono, monospace' }}>
                            <td style={{ padding: '10px 12px', color: '#64748b', whiteSpace: 'nowrap', fontSize: '0.75rem' }}>
                              {nl.timestamp ? new Date(nl.timestamp).toLocaleTimeString() : '—'}
                            </td>
                            <td style={{ padding: '10px 12px', color: isDns ? '#06b6d4' : '#8b5cf6', fontWeight: 700 }}>
                              {nl.source || (isDns ? 'dns_cache' : 'kernel_socket')}
                            </td>
                            <td style={{ padding: '10px 12px' }}>
                              {isDns ? (
                                <span style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: 4,
                                  padding: '2px 8px',
                                  borderRadius: 4,
                                  fontSize: '0.68rem',
                                  fontWeight: 800,
                                  background: 'rgba(6, 182, 212, 0.15)',
                                  color: '#06b6d4',
                                  border: '1px solid rgba(6, 182, 212, 0.4)'
                                }}>
                                  <Globe size={10} /> DNS QUERY
                                </span>
                              ) : (
                                <span style={{
                                  display: 'inline-block',
                                  padding: '2px 8px',
                                  borderRadius: 4,
                                  fontSize: '0.68rem',
                                  fontWeight: 800,
                                  background: 'rgba(139, 92, 246, 0.15)',
                                  color: '#a78bfa',
                                  border: '1px solid rgba(139, 92, 246, 0.4)'
                                }}>
                                  {nl.event_id || 'SOCKET'}
                                </span>
                              )}
                            </td>
                            <td style={{ padding: '10px 12px', color: '#f8fafc', wordBreak: 'break-all' }}>
                              {isDns ? (
                                <span style={{ color: '#38bdf8', fontWeight: 800, fontSize: '0.84rem' }}>
                                  {nl.message}
                                </span>
                              ) : (
                                <span>
                                  {nl.message}
                                </span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TAB 3: LIVE TELEMETRY & PROCESSES ── */}
      {activeTab === 'telemetry' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Real Metrics Gauge */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
            <div className="bento-card bento-card-cyan" style={{ padding: 18 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <Cpu size={16} color="#06b6d4" />
                <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>
                  CPU UTILIZATION
                </span>
              </div>
              <p style={{ margin: 0, fontSize: '1.8rem', fontWeight: 800, color: '#f8fafc' }}>
                {latestMetric ? `${latestMetric.cpu_percent}%` : '—'}
              </p>
            </div>

            <div className="bento-card bento-card-violet" style={{ padding: 18 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <HardDrive size={16} color="#8b5cf6" />
                <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>
                  MEMORY USAGE
                </span>
              </div>
              <p style={{ margin: 0, fontSize: '1.8rem', fontWeight: 800, color: '#f8fafc' }}>
                {latestMetric ? `${latestMetric.memory_percent}%` : '—'}
              </p>
              {latestMetric?.memory_used_mb && (
                <span style={{ fontSize: '0.7rem', color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>
                  {latestMetric.memory_used_mb} MB / {latestMetric.memory_total_mb} MB
                </span>
              )}
            </div>

            <div className="bento-card bento-card-emerald" style={{ padding: 18 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <Radio size={16} color="#10b981" />
                <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>
                  NETWORK RX / TX
                </span>
              </div>
              <p style={{ margin: 0, fontSize: '1.3rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'JetBrains Mono, monospace' }}>
                {latestMetric ? `${((latestMetric.network_rx_bytes || 0) / (1024 * 1024)).toFixed(1)} MB ↓` : '—'}
              </p>
              <span style={{ fontSize: '0.72rem', color: '#10b981', fontFamily: 'JetBrains Mono, monospace' }}>
                {latestMetric ? `${((latestMetric.network_tx_bytes || 0) / (1024 * 1024)).toFixed(1)} MB ↑` : '—'}
              </span>
            </div>
          </div>

          {/* Real Metrics Timeline Chart (ONLY REAL DATA) */}
          <div className="bento-card" style={{ padding: 22 }}>
            <h3 style={{ margin: '0 0 16px', fontSize: '0.95rem', fontWeight: 800, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Activity size={15} color="#06b6d4" /> Telemetry Timeline ({metrics.length} real samples)
            </h3>
            {metrics.length === 0 ? (
              <div style={{ padding: 40, textAlign: 'center', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem' }}>
                No metric samples collected yet. Agent will stream CPU/Memory/Network samples every 10 seconds.
              </div>
            ) : (
              <div style={{ height: 220 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={metrics} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#161e30" />
                    <XAxis dataKey="timestamp" stroke="transparent" tick={{ fill: '#64748b', fontSize: 10 }} />
                    <YAxis stroke="transparent" tick={{ fill: '#64748b', fontSize: 10 }} domain={[0, 100]} unit="%" />
                    <Tooltip contentStyle={{ background: '#070a11', border: '2px solid #1e293b', borderRadius: 8, fontSize: 11 }} />
                    <Area type="monotone" dataKey="cpu_percent" name="CPU %" stroke="#06b6d4" strokeWidth={2} fill="#06b6d420" />
                    <Area type="monotone" dataKey="memory_percent" name="Memory %" stroke="#8b5cf6" strokeWidth={2} fill="#8b5cf620" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          {/* Real Active Process Table */}
          <div className="bento-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div>
                <h3 style={{ margin: '0 0 4px', fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
                  Active Endpoint Processes ({processes.length})
                </h3>
                <p style={{ margin: 0, fontSize: '0.78rem', color: '#64748b' }}>
                  Live process tree inspected on {device.hostname} by universal agent
                </p>
              </div>
            </div>

            {processes.length === 0 ? (
              <div style={{ padding: 30, textAlign: 'center', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem' }}>
                Awaiting process snapshot from endpoint...
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #1e293b', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}>
                      <th style={{ padding: '8px 12px' }}>PID</th>
                      <th style={{ padding: '8px 12px' }}>PROCESS NAME</th>
                      <th style={{ padding: '8px 12px' }}>CPU %</th>
                      <th style={{ padding: '8px 12px' }}>MEM %</th>
                      <th style={{ padding: '8px 12px' }}>USER</th>
                      <th style={{ padding: '8px 12px' }}>EXECUTABLE PATH</th>
                    </tr>
                  </thead>
                  <tbody>
                    {processes.slice(0, 30).map((p: any) => (
                      <tr key={p.pid} style={{ borderBottom: '1px solid #161e30', fontFamily: 'JetBrains Mono, monospace' }}>
                        <td style={{ padding: '8px 12px', color: '#06b6d4', fontWeight: 700 }}>
                          {p.pid}
                        </td>
                        <td style={{ padding: '8px 12px', color: '#f8fafc', fontWeight: 700 }}>
                          {p.name}
                        </td>
                        <td style={{ padding: '8px 12px', color: p.cpu_percent > 50 ? '#f43f5e' : '#cbd5e1' }}>
                          {p.cpu_percent?.toFixed(1) || '0.0'}%
                        </td>
                        <td style={{ padding: '8px 12px', color: '#cbd5e1' }}>
                          {p.memory_percent?.toFixed(1) || '0.0'}%
                        </td>
                        <td style={{ padding: '8px 12px', color: '#8b5cf6' }}>
                          {p.username || 'system'}
                        </td>
                        <td style={{ padding: '8px 12px', color: '#64748b', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {p.executable || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TAB 4: AUDIT TIMELINE ── */}
      {activeTab === 'timeline' && (
        <div className="bento-card" style={{ padding: 22 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
            Endpoint Audit &amp; Event Timeline ({events.length})
          </h3>
          {events.length === 0 ? (
            <p style={{ color: '#64748b', fontSize: '0.82rem', fontFamily: 'JetBrains Mono, monospace' }}>
              No administrative events recorded for this device yet.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {events.map((evt: any, i: number) => {
                const s = EVENT_STYLES[evt.event] || { color: '#94a3b8', bg: 'rgba(100,116,139,0.08)', dot: '#94a3b8' };
                return (
                  <div 
                    key={evt._id || i}
                    style={{
                      background: s.bg, border: `1.5px solid ${s.color}35`,
                      borderRadius: 8, padding: '12px 16px', display: 'flex',
                      alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{ width: 10, height: 10, borderRadius: '50%', background: s.dot }} />
                      <span style={{ fontWeight: 800, color: s.color, fontSize: '0.85rem', textTransform: 'uppercase', fontFamily: 'JetBrains Mono, monospace' }}>
                        {evt.event}
                      </span>
                      <span style={{ color: '#cbd5e1', fontSize: '0.82rem' }}>
                        {evt.details}
                      </span>
                    </div>
                    <span style={{ color: '#64748b', fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace' }}>
                      {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : '—'}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

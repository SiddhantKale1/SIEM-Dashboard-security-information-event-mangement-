import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  TrendingUp, 
  Server, 
  Flame, 
  ArrowUpRight, 
  RefreshCw,
  Zap
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import api from '../services/api';

export default function Dashboard() {
  const navigate = useNavigate();
  const [logVolume, setLogVolume] = useState<{ time: string; count: number }[]>([]);
  const [logStats, setLogStats] = useState({ logs_today: 0, logs_total: 0, errors: 0, warnings: 0 });
  const [aiStats, setAiStats] = useState({
    risk_score: 0,
    posture: 'SECURE',
    active_threats: 0,
    critical_threats: 0,
    total_anomalies: 0,
    mitre_distribution: [] as { tactic: string; count: number }[]
  });
  const [networkInfo, setNetworkInfo] = useState<any>({
    network: null,
    active_devices_count: 0,
    aggregate_tx_bytes: 0,
    aggregate_rx_bytes: 0
  });
  const [activeThreatsList, setActiveThreatsList] = useState<any[]>([]);
  const [activeDevicesList, setActiveDevicesList] = useState<any[]>([]);

  const loadDashboardData = useCallback(async () => {
    try {
      const [hourlyRes, statsRes, aiRes, netRes, anomaliesRes, devRes] = await Promise.all([
        api.get('/logs/hourly').catch(() => ({ data: [] })),
        api.get('/logs/stats').catch(() => ({ data: { logs_today: 0, logs_total: 0, errors: 0, warnings: 0 } })),
        api.get('/anomalies/stats').catch(() => ({ data: { risk_score: 0, posture: 'SECURE', active_threats: 0, critical_threats: 0, mitre_distribution: [] } })),
        api.get('/network/traffic').catch(() => ({ data: {} })),
        api.get('/anomalies?status=active&limit=4').catch(() => ({ data: { anomalies: [] } })),
        api.get('/network/active').catch(() => ({ data: { devices: [] } }))
      ]);

      setLogVolume(hourlyRes.data || []);
      setLogStats(statsRes.data || {});
      setAiStats(aiRes.data || {});
      setNetworkInfo(netRes.data || {});
      setActiveThreatsList(anomaliesRes.data?.anomalies || []);
      setActiveDevicesList(devRes.data?.devices || []);
    } catch (e) {
      console.error("Dashboard fetch error:", e);
    }
  }, []);

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 12000);
    return () => clearInterval(interval);
  }, [loadDashboardData]);

  const handleIsolateDevice = async (deviceId: string) => {
    try {
      await api.post(`/devices/${deviceId}/isolate`);
      loadDashboardData();
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Isolation failed");
    }
  };

  const getPostureColor = (posture: string) => {
    switch (posture) {
      case 'CRITICAL': return '#f43f5e';
      case 'ELEVATED': return '#f59e0b';
      case 'MONITORED': return '#06b6d4';
      default: return '#10b981';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Top Header Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, margin: 0, letterSpacing: '-0.03em', color: '#f8fafc' }}>
              Command Bento
            </h1>
            <span className="neo-badge neo-badge-violet">
              AI REAL-TIME ENGINE
            </span>
          </div>
          <p style={{ margin: '4px 0 0', fontSize: '0.85rem', color: '#64748b' }}>
            Autonomous threat detection, dynamic network telemetry, and permanent endpoint stream
          </p>
        </div>

        {/* Quick Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button 
            onClick={() => loadDashboardData()}
            className="neo-btn neo-btn-ghost"
            style={{ padding: '8px 14px', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
          <button 
            onClick={() => navigate('/simulator')}
            className="neo-btn neo-btn-violet"
            style={{ padding: '8px 14px', fontSize: '0.8rem' }}
          >
            <Flame size={14} /> Attack Lab
          </button>
          <button 
            onClick={() => navigate('/endpoints')}
            className="neo-btn neo-btn-cyan"
            style={{ padding: '8px 14px', fontSize: '0.8rem' }}
          >
            <Zap size={14} /> Deploy Agent
          </button>
        </div>
      </div>

      {/* ── BENTO GRID ── */}
      <div className="bento-grid">

        {/* BENTO TILE 1: AI Defense Matrix (Span 8) */}
        <div 
          className="bento-card" 
          style={{ 
            gridColumn: 'span 8', 
            padding: 24, 
            borderColor: aiStats.critical_threats > 0 ? '#f43f5e' : aiStats.active_threats > 0 ? '#f59e0b' : '#1e293b'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="neo-badge" style={{ background: '#8b5cf6', color: '#fff' }}>
                  AI THREAT RADAR
                </span>
                <span className="pulse-dot" style={{
                  width: 8, height: 8, borderRadius: '50%',
                  background: getPostureColor(aiStats.posture)
                }} />
              </div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, margin: '8px 0 2px', color: '#f8fafc' }}>
                System Threat Posture: <span style={{ color: getPostureColor(aiStats.posture) }}>{aiStats.posture}</span>
              </h2>
              <p style={{ margin: 0, fontSize: '0.82rem', color: '#64748b' }}>
                Multi-signal heuristic & statistical anomaly evaluation active
              </p>
            </div>

            {/* Risk Score Circle */}
            <div style={{
              background: '#070a11',
              border: `2.5px solid ${getPostureColor(aiStats.posture)}`,
              borderRadius: 12,
              padding: '10px 18px',
              textAlign: 'center',
              boxShadow: `3px 3px 0px ${getPostureColor(aiStats.posture)}`
            }}>
              <div style={{ fontSize: '0.68rem', fontFamily: 'JetBrains Mono, monospace', color: '#94a3b8', fontWeight: 700 }}>
                RISK SCORE
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 900, color: getPostureColor(aiStats.posture), lineHeight: 1 }}>
                {aiStats.risk_score}
                <span style={{ fontSize: '0.9rem', color: '#64748b' }}>/100</span>
              </div>
            </div>
          </div>

          {/* Quick Threat Metrics Row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginTop: 16 }}>
            <div style={{ background: '#0a0f1a', border: '2px solid #1e293b', borderRadius: 8, padding: '12px 14px' }}>
              <div style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 700 }}>ACTIVE THREATS</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: aiStats.active_threats > 0 ? '#f43f5e' : '#10b981', marginTop: 4 }}>
                {aiStats.active_threats}
              </div>
            </div>
            <div style={{ background: '#0a0f1a', border: '2px solid #1e293b', borderRadius: 8, padding: '12px 14px' }}>
              <div style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 700 }}>CRITICAL INCIDENTS</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: aiStats.critical_threats > 0 ? '#f43f5e' : '#94a3b8', marginTop: 4 }}>
                {aiStats.critical_threats}
              </div>
            </div>
            <div style={{ background: '#0a0f1a', border: '2px solid #1e293b', borderRadius: 8, padding: '12px 14px' }}>
              <div style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 700 }}>MITRE TACTICS HIT</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#8b5cf6', marginTop: 4 }}>
                {aiStats.mitre_distribution?.length || 0}
              </div>
            </div>
            <div style={{ background: '#0a0f1a', border: '2px solid #1e293b', borderRadius: 8, padding: '12px 14px' }}>
              <div style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 700 }}>RESOLVED ATTACKS</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#10b981', marginTop: 4 }}>
                {aiStats.total_anomalies - aiStats.active_threats}
              </div>
            </div>
          </div>
        </div>

        {/* BENTO TILE 2: Active Network Pulse (Span 4) */}
        <div className="bento-card bento-card-cyan" style={{ gridColumn: 'span 4', padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span className="neo-badge neo-badge-cyan">
              NETWORK PULSE
            </span>
            <span style={{ fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', color: '#06b6d4', fontWeight: 700 }}>
              {networkInfo.network?.subnet || '—'}
            </span>
          </div>

          <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc', margin: '0 0 4px' }}>
            Current Connected Scope
          </h3>
          <p style={{ fontSize: '0.78rem', color: '#64748b', margin: '0 0 16px' }}>
            Only displays systems actively communicating on current network
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: '#080c14', borderRadius: 6, border: '1.5px solid #1e293b' }}>
              <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>Live Nodes on Subnet:</span>
              <span style={{ fontSize: '0.85rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, color: '#10b981' }}>
                {networkInfo.active_devices_count || 0} active
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: '#080c14', borderRadius: 6, border: '1.5px solid #1e293b' }}>
              <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>Default Gateway:</span>
              <span style={{ fontSize: '0.85rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, color: '#38bdf8' }}>
                {networkInfo.network?.gateway || '—'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: '#080c14', borderRadius: 6, border: '1.5px solid #1e293b' }}>
              <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>Session History Count:</span>
              <span style={{ fontSize: '0.85rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, color: '#c084fc' }}>
                {networkInfo.history_sessions_count || 0} past sessions
              </span>
            </div>
          </div>

          <button 
            onClick={() => navigate('/network')}
            className="neo-btn neo-btn-ghost" 
            style={{ width: '100%', marginTop: 16, padding: '8px 12px', fontSize: '0.8rem' }}
          >
            View Network Traffic & History <ArrowUpRight size={14} />
          </button>
        </div>

        {/* BENTO TILE 3: Real-Time Log Volume Area Chart (Span 8) */}
        <div className="bento-card" style={{ gridColumn: 'span 8', padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <TrendingUp size={18} color="#06b6d4" />
              <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
                Log Ingestion Velocity (Last 24 Hours)
              </h3>
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
              <span className="mono-pill">Total: {logStats.logs_today || 0}</span>
              <span className="mono-pill" style={{ borderColor: '#f43f5e', color: '#f43f5e' }}>Errors: {logStats.errors || 0}</span>
              <span className="mono-pill" style={{ borderColor: '#f59e0b', color: '#f59e0b' }}>Warnings: {logStats.warnings || 0}</span>
            </div>
          </div>

          <div style={{ height: 210 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={logVolume} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradCyan" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 11 }} tickLine={false} />
                <YAxis stroke="#475569" tick={{ fontSize: 11 }} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: '#0b0f19', border: '2px solid #06b6d4', borderRadius: 8, color: '#f8fafc', boxShadow: '3px 3px 0px #000' }}
                  labelStyle={{ color: '#38bdf8', fontWeight: 700 }}
                />
                <Area 
                  type="monotone" 
                  dataKey="count" 
                  stroke="#06b6d4" 
                  strokeWidth={2.5} 
                  fill="url(#gradCyan)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* BENTO TILE 4: Active Threat Stream (Span 4) */}
        <div className="bento-card bento-card-coral" style={{ gridColumn: 'span 4', padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span className="neo-badge neo-badge-critical">
              INCIDENT STREAM
            </span>
            <button 
              onClick={() => navigate('/threats')}
              style={{ background: 'none', border: 'none', color: '#f43f5e', fontSize: '0.75rem', fontWeight: 700, cursor: 'pointer' }}
            >
              All Threats &rarr;
            </button>
          </div>

          <h3 style={{ fontSize: '1rem', fontWeight: 800, color: '#f8fafc', margin: '0 0 12px' }}>
            Latest AI Detections
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 220, overflowY: 'auto' }}>
            {activeThreatsList.length === 0 ? (
              <div style={{
                padding: '24px 12px', textAlign: 'center', background: '#080c14',
                borderRadius: 8, border: '1.5px solid #1e293b', color: '#64748b'
              }}>
                <div style={{ color: '#10b981', fontWeight: 700, fontSize: '0.9rem', marginBottom: 4 }}>No Active Threats</div>
                <div style={{ fontSize: '0.75rem' }}>AI Detection Engine is monitoring all streams.</div>
              </div>
            ) : (
              activeThreatsList.map((anom: any) => (
                <div 
                  key={anom._id} 
                  style={{
                    background: '#090d16',
                    border: '1.5px solid #1e293b',
                    borderLeft: `4px solid ${anom.severity === 'critical' ? '#f43f5e' : '#f59e0b'}`,
                    borderRadius: 6,
                    padding: '8px 10px'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f1f5f9' }}>
                      {anom.title?.slice(0, 32)}...
                    </span>
                    <span className={`neo-badge neo-badge-${anom.severity}`}>
                      {anom.mitre_id || anom.severity}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 6 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ color: '#06b6d4', fontWeight: 800 }}>🖥️ {anom.hostname}</span>
                      {anom.ip_address && (
                        <span style={{ color: '#94a3b8', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.68rem' }}>
                          ({anom.ip_address})
                        </span>
                      )}
                    </div>
                    <div style={{ display: 'flex', gap: 6 }}>
                      {anom.device_id && (
                        <button 
                          onClick={() => navigate(`/devices/${anom.device_id}`)}
                          style={{
                            background: 'rgba(6, 182, 212, 0.15)', color: '#06b6d4', border: '1px solid rgba(6, 182, 212, 0.4)',
                            fontSize: '0.65rem', fontWeight: 700, padding: '2px 6px', borderRadius: 4, cursor: 'pointer'
                          }}
                        >
                          Inspect
                        </button>
                      )}
                      <button 
                        onClick={() => handleIsolateDevice(anom.device_id)}
                        style={{
                          background: '#f43f5e', color: '#fff', border: '1px solid #000',
                          fontSize: '0.65rem', fontWeight: 700, padding: '2px 6px', borderRadius: 4, cursor: 'pointer'
                        }}
                      >
                        Isolate
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* BENTO TILE 5: Current Network Active Systems (Span 12) */}
        <div className="bento-card" style={{ gridColumn: 'span 12', padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Server size={18} color="#10b981" />
              <div>
                <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
                  Connected Systems on Active Network ({activeDevicesList.length})
                </h3>
                <p style={{ margin: 0, fontSize: '0.75rem', color: '#64748b' }}>
                  Dynamically updated: past networks & offline sessions are moved to the Connection History tab
                </p>
              </div>
            </div>
            <button 
              onClick={() => navigate('/network')}
              className="neo-btn neo-btn-ghost"
              style={{ padding: '6px 12px', fontSize: '0.75rem' }}
            >
              Network Center &rarr;
            </button>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #1e293b', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem' }}>
                  <th style={{ padding: '8px 12px' }}>STATUS</th>
                  <th style={{ padding: '8px 12px' }}>HOSTNAME</th>
                  <th style={{ padding: '8px 12px' }}>IP ADDRESS</th>
                  <th style={{ padding: '8px 12px' }}>MAC ADDRESS</th>
                  <th style={{ padding: '8px 12px' }}>OS</th>
                  <th style={{ padding: '8px 12px' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {activeDevicesList.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ padding: '24px 12px', textAlign: 'center', color: '#475569' }}>
                      No active systems currently reporting on {networkInfo.network?.subnet || 'local network'}.
                    </td>
                  </tr>
                ) : (
                  activeDevicesList.slice(0, 6).map((dev: any) => (
                    <tr 
                      key={dev._id} 
                      style={{ borderBottom: '1px solid #151d2e', transition: 'background 0.1s' }}
                      onMouseEnter={e => e.currentTarget.style.background = '#0e1524'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <td style={{ padding: '10px 12px' }}>
                        <span className={`neo-badge neo-badge-${dev.status === 'isolated' ? 'isolated' : dev.current_network_state === 'online' ? 'online' : 'offline'}`}>
                          {dev.status === 'isolated' ? 'ISOLATED' : dev.current_network_state || 'ONLINE'}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', fontWeight: 700, color: '#f1f5f9' }}>
                        {dev.hostname || 'Unknown Host'}
                      </td>
                      <td style={{ padding: '10px 12px', fontFamily: 'JetBrains Mono, monospace', color: '#38bdf8' }}>
                        {dev.ip_address}
                      </td>
                      <td style={{ padding: '10px 12px', fontFamily: 'JetBrains Mono, monospace', color: '#64748b' }}>
                        {dev.mac_address}
                      </td>
                      <td style={{ padding: '10px 12px', textTransform: 'capitalize', color: '#cbd5e1' }}>
                        {dev.os}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        {dev.status === 'isolated' ? (
                          <button
                            onClick={() => api.post(`/devices/${dev.device_id}/restore`).then(() => loadDashboardData())}
                            className="neo-btn neo-btn-emerald"
                            style={{ padding: '4px 8px', fontSize: '0.7rem' }}
                          >
                            Restore
                          </button>
                        ) : dev.device_id ? (
                          <button
                            onClick={() => handleIsolateDevice(dev.device_id)}
                            className="neo-btn neo-btn-coral"
                            style={{ padding: '4px 8px', fontSize: '0.7rem' }}
                          >
                            Isolate
                          </button>
                        ) : (
                          <span style={{ fontSize: '0.7rem', color: '#475569' }}>Unmanaged</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}

import { useState, useEffect } from 'react';
import { 
  Radio, 
  History, 
  RefreshCw, 
  Search, 
  Lock, 
  Unlock
} from 'lucide-react';
import api from '../services/api';

export default function NetworkTraffic() {
  const [activeTab, setActiveTab] = useState<'active' | 'history'>('active');
  const [trafficData, setTrafficData] = useState<any>({
    network: null,
    active_devices_count: 0,
    aggregate_tx_bytes: 0,
    aggregate_rx_bytes: 0,
    history_sessions_count: 0
  });
  const [activeDevices, setActiveDevices] = useState<any[]>([]);
  const [connectionHistory, setConnectionHistory] = useState<any[]>([]);
  const [scanning, setScanning] = useState(false);
  const [search, setSearch] = useState('');

  const loadData = async (forceScan: boolean = false) => {
    if (forceScan) setScanning(true);

    try {
      const [trafficRes, activeRes, histRes] = await Promise.all([
        api.get('/network/traffic'),
        api.get(`/network/active${forceScan ? '?scan=true' : ''}`),
        api.get('/network/history?limit=100')
      ]);

      setTrafficData(trafficRes.data || {});
      setActiveDevices(activeRes.data?.devices || []);
      setConnectionHistory(histRes.data?.history || []);
    } catch (err) {
      console.error("Failed to load network traffic data:", err);
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(false), 15000);
    return () => clearInterval(interval);
  }, []);

  const handleIsolate = async (deviceId: string) => {
    try {
      await api.post(`/devices/${deviceId}/isolate`);
      loadData(false);
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Isolation failed");
    }
  };

  const handleRestore = async (deviceId: string) => {
    try {
      await api.post(`/devices/${deviceId}/restore`);
      loadData(false);
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Restore failed");
    }
  };

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  const filteredActiveDevices = activeDevices.filter(d => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      d.hostname?.toLowerCase().includes(q) ||
      d.ip_address?.toLowerCase().includes(q) ||
      d.mac_address?.toLowerCase().includes(q) ||
      d.os?.toLowerCase().includes(q)
    );
  });

  const filteredHistory = connectionHistory.filter(h => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      h.hostname?.toLowerCase().includes(q) ||
      h.ip_address?.toLowerCase().includes(q) ||
      h.subnet?.toLowerCase().includes(q) ||
      h.termination_reason?.toLowerCase().includes(q)
    );
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, margin: 0, letterSpacing: '-0.03em', color: '#f8fafc' }}>
              Network Traffic & Active Systems
            </h1>
            <span className="neo-badge neo-badge-cyan">
              SUBNET: {trafficData.network?.subnet || '—'}
            </span>
          </div>
          <p style={{ margin: '4px 0 0', fontSize: '0.85rem', color: '#64748b' }}>
            Real-time active network segregation — past networks are automatically cataloged in Connection History
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button 
            onClick={() => loadData(true)}
            disabled={scanning}
            className="neo-btn neo-btn-cyan"
            style={{ padding: '8px 14px', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} className={scanning ? 'radar-spinner' : ''} />
            {scanning ? 'Sweeping Subnet ARP...' : 'Scan Active Subnet'}
          </button>
        </div>
      </div>

      {/* Top Bento Stats Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
        <div className="bento-card" style={{ padding: '16px 20px', borderColor: '#06b6d4' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 700 }}>ACTIVE SUBNET</div>
          <div style={{ fontSize: '1.35rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, color: '#06b6d4', marginTop: 4 }}>
            {trafficData.network?.subnet}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: 2 }}>
            Gateway: {trafficData.network?.gateway}
          </div>
        </div>

        <div className="bento-card" style={{ padding: '16px 20px', borderColor: '#10b981' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 700 }}>LIVE CONNECTED NODES</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 900, color: '#10b981', marginTop: 4 }}>
            {trafficData.active_devices_count} <span style={{ fontSize: '0.8rem', color: '#64748b' }}>systems</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: 2 }}>
            Active within last 90s
          </div>
        </div>

        <div className="bento-card" style={{ padding: '16px 20px', borderColor: '#8b5cf6' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 700 }}>AGGREGATE NETWORK TRAFFIC</div>
          <div style={{ fontSize: '1.35rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, color: '#8b5cf6', marginTop: 4 }}>
            TX: {formatBytes(trafficData.aggregate_tx_bytes)}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: 2 }}>
            RX: {formatBytes(trafficData.aggregate_rx_bytes)}
          </div>
        </div>

        <div className="bento-card" style={{ padding: '16px 20px', borderColor: '#334155' }}>
          <div style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 700 }}>CONNECTION SESSIONS AUDITED</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 900, color: '#f8fafc', marginTop: 4 }}>
            {trafficData.history_sessions_count} <span style={{ fontSize: '0.8rem', color: '#64748b' }}>sessions</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: 2 }}>
            Historical network switches tracked
          </div>
        </div>
      </div>

      {/* Tabs and Search Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        {/* Navigation Tabs */}
        <div style={{ display: 'flex', background: '#0a0e17', border: '2.5px solid #1e293b', borderRadius: 10, padding: 3 }}>
          <button
            onClick={() => setActiveTab('active')}
            style={{
              background: activeTab === 'active' ? '#06b6d4' : 'transparent',
              color: activeTab === 'active' ? '#041017' : '#94a3b8',
              border: activeTab === 'active' ? '2px solid #000' : 'none',
              borderRadius: 7,
              padding: '8px 18px',
              fontSize: '0.82rem',
              fontWeight: 800,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              boxShadow: activeTab === 'active' ? '2px 2px 0px #000' : 'none',
              transition: 'all 0.1s ease'
            }}
          >
            <Radio size={15} /> Active Systems ({activeDevices.length})
          </button>

          <button
            onClick={() => setActiveTab('history')}
            style={{
              background: activeTab === 'history' ? '#8b5cf6' : 'transparent',
              color: activeTab === 'history' ? '#ffffff' : '#94a3b8',
              border: activeTab === 'history' ? '2px solid #000' : 'none',
              borderRadius: 7,
              padding: '8px 18px',
              fontSize: '0.82rem',
              fontWeight: 800,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              boxShadow: activeTab === 'history' ? '2px 2px 0px #000' : 'none',
              transition: 'all 0.1s ease'
            }}
          >
            <History size={15} /> Connection History ({connectionHistory.length})
          </button>
        </div>

        {/* Search */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          background: '#0d131f', border: '2px solid #1e293b',
          borderRadius: 8, padding: '6px 12px', minWidth: 260
        }}>
          <Search size={15} color="#64748b" />
          <input 
            type="text" 
            placeholder={activeTab === 'active' ? 'Search active endpoints...' : 'Search past sessions, subnets, IPs...'}
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              background: 'transparent', border: 'none', color: '#f8fafc',
              fontSize: '0.82rem', outline: 'none', width: '100%', fontFamily: 'inherit'
            }}
          />
        </div>
      </div>

      {/* ── TAB 1: ACTIVE CURRENT NETWORK SYSTEMS ── */}
      {activeTab === 'active' && (
        <div className="bento-card" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <h3 style={{ margin: '0 0 4px', fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc' }}>
                Endpoints Online on {trafficData.network?.subnet || 'Active Network'}
              </h3>
              <p style={{ margin: 0, fontSize: '0.8rem', color: '#64748b' }}>
                When you switch networks or an endpoint leaves this subnet, it is cleanly removed from this view and saved to History.
              </p>
            </div>
            <span className="mono-pill" style={{ color: '#10b981', borderColor: '#10b981' }}>
              STRICT SUBNET FILTERING ACTIVE
            </span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.84rem' }}>
              <thead>
                <tr style={{ borderBottom: '2.5px solid #1e293b', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem' }}>
                  <th style={{ padding: '10px 14px' }}>HEALTH</th>
                  <th style={{ padding: '10px 14px' }}>HOSTNAME</th>
                  <th style={{ padding: '10px 14px' }}>IP ADDRESS</th>
                  <th style={{ padding: '10px 14px' }}>MAC ADDRESS</th>
                  <th style={{ padding: '10px 14px' }}>OPERATING SYSTEM</th>
                  <th style={{ padding: '10px 14px' }}>LAST SEEN</th>
                  <th style={{ padding: '10px 14px' }}>SECURITY ACTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredActiveDevices.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ padding: '40px 14px', textAlign: 'center', color: '#475569' }}>
                      No active systems currently discovered on {trafficData.network?.subnet || 'local network'}.
                    </td>
                  </tr>
                ) : (
                  filteredActiveDevices.map((dev: any) => (
                    <tr 
                      key={dev._id} 
                      style={{ borderBottom: '1px solid #161e30', transition: 'background 0.1s' }}
                      onMouseEnter={e => e.currentTarget.style.background = '#0e1524'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <td style={{ padding: '12px 14px' }}>
                        <span className={`neo-badge neo-badge-${dev.status === 'isolated' ? 'isolated' : dev.current_network_state === 'online' ? 'online' : 'offline'}`}>
                          {dev.status === 'isolated' ? 'ISOLATED' : dev.current_network_state || 'ONLINE'}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px', fontWeight: 800, color: '#f8fafc' }}>
                        {dev.hostname || 'Unknown Endpoint'}
                      </td>
                      <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono, monospace', color: '#06b6d4', fontWeight: 700 }}>
                        {dev.ip_address}
                      </td>
                      <td style={{ padding: '12px 14px', fontFamily: 'JetBrains Mono, monospace', color: '#64748b' }}>
                        {dev.mac_address}
                      </td>
                      <td style={{ padding: '12px 14px', textTransform: 'capitalize', color: '#cbd5e1' }}>
                        {dev.os} {dev.os_version ? `(${dev.os_version.slice(0, 10)})` : ''}
                      </td>
                      <td style={{ padding: '12px 14px', fontSize: '0.75rem', color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>
                        {dev.last_seen ? new Date(dev.last_seen).toLocaleTimeString() : 'Just now'}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        {dev.status === 'isolated' ? (
                          <button
                            onClick={() => handleRestore(dev.device_id)}
                            className="neo-btn neo-btn-emerald"
                            style={{ padding: '5px 10px', fontSize: '0.72rem' }}
                          >
                            <Unlock size={12} /> Restore Access
                          </button>
                        ) : dev.device_id ? (
                          <button
                            onClick={() => handleIsolate(dev.device_id)}
                            className="neo-btn neo-btn-coral"
                            style={{ padding: '5px 10px', fontSize: '0.72rem' }}
                          >
                            <Lock size={12} /> Isolate Device
                          </button>
                        ) : (
                          <span style={{ fontSize: '0.72rem', color: '#64748b' }}>Unmanaged ARP</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── TAB 2: CONNECTION HISTORY ── */}
      {activeTab === 'history' && (
        <div className="bento-card" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <h3 style={{ margin: '0 0 4px', fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc' }}>
                Endpoint Connection & Session History ({connectionHistory.length})
              </h3>
              <p style={{ margin: 0, fontSize: '0.8rem', color: '#64748b' }}>
                Complete chronological audit of all past networks, disconnect timestamps, and transmitted volume
              </p>
            </div>
            <span className="mono-pill" style={{ color: '#8b5cf6', borderColor: '#8b5cf6' }}>
              AUDIT LOG
            </span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ borderBottom: '2.5px solid #1e293b', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem' }}>
                  <th style={{ padding: '10px 12px' }}>SESSION STATUS</th>
                  <th style={{ padding: '10px 12px' }}>HOSTNAME</th>
                  <th style={{ padding: '10px 12px' }}>IP & SUBNET</th>
                  <th style={{ padding: '10px 12px' }}>CONNECTED AT</th>
                  <th style={{ padding: '10px 12px' }}>DISCONNECTED / SWITCHED</th>
                  <th style={{ padding: '10px 12px' }}>DURATION</th>
                  <th style={{ padding: '10px 12px' }}>LOGS PROCESSED</th>
                  <th style={{ padding: '10px 12px' }}>DISCONNECT REASON</th>
                </tr>
              </thead>
              <tbody>
                {filteredHistory.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ padding: '40px 12px', textAlign: 'center', color: '#475569' }}>
                      No connection history sessions recorded yet.
                    </td>
                  </tr>
                ) : (
                  filteredHistory.map((sess: any) => (
                    <tr 
                      key={sess._id} 
                      style={{ borderBottom: '1px solid #161e30', transition: 'background 0.1s' }}
                      onMouseEnter={e => e.currentTarget.style.background = '#0e1524'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <td style={{ padding: '10px 12px' }}>
                        <span className={`neo-badge ${sess.status === 'active' ? 'neo-badge-online' : 'neo-badge-offline'}`}>
                          {sess.status === 'active' ? 'ACTIVE SESSION' : 'CLOSED'}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', fontWeight: 700, color: '#f8fafc' }}>
                        {sess.hostname}
                      </td>
                      <td style={{ padding: '10px 12px', fontFamily: 'JetBrains Mono, monospace' }}>
                        <div style={{ color: '#06b6d4', fontWeight: 700 }}>{sess.ip_address}</div>
                        <div style={{ fontSize: '0.72rem', color: '#64748b' }}>{sess.subnet}</div>
                      </td>
                      <td style={{ padding: '10px 12px', fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', color: '#94a3b8' }}>
                        {new Date(sess.connected_at).toLocaleString()}
                      </td>
                      <td style={{ padding: '10px 12px', fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', color: '#94a3b8' }}>
                        {sess.disconnected_at ? new Date(sess.disconnected_at).toLocaleString() : 'Currently Active'}
                      </td>
                      <td style={{ padding: '10px 12px', fontFamily: 'JetBrains Mono, monospace', color: '#c084fc' }}>
                        {sess.duration_seconds ? `${Math.floor(sess.duration_seconds / 60)}m ${sess.duration_seconds % 60}s` : 'Ongoing'}
                      </td>
                      <td style={{ padding: '10px 12px', fontFamily: 'JetBrains Mono, monospace', color: '#38bdf8' }}>
                        {sess.logs_sent || 0} events
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span className="mono-pill">
                          {sess.termination_reason || 'active_connection'}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
}

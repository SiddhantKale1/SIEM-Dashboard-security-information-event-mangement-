import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useDevices } from '../context/DeviceContext';
import api from '../services/api';
import { Search, Plus, RefreshCw, Server, Copy, Check } from 'lucide-react';
import { format } from 'date-fns';

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`badge badge-${status || 'offline'}`}>
      <span className={`status-dot ${status || 'offline'}`} />
      {status || 'offline'}
    </span>
  );
}

export default function Devices() {
  const { devices, loading, fetchDevices, invalidate } = useDevices();
  const [search, setSearch]       = useState('');
  const [enrollToken, setEnrollToken] = useState('');
  const [scanning, setScanning]   = useState(false);
  const [copied, setCopied]       = useState(false);

  useEffect(() => { fetchDevices(false); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleScan = async () => {
    setScanning(true);
    await fetchDevices(true);
    setScanning(false);
  };

  const generateToken = async () => {
    try {
      const res = await api.post('/enrollment/token');
      setEnrollToken(res.data.token);
      invalidate();
    } catch (err) { console.error(err); }
  };

  const copyCmd = () => {
    const cmd = `export ENROLLMENT_TOKEN="${enrollToken}" && export SERVER_URL="http://127.0.0.1:8002" && cd /home/sidd/SIEM/agents/linux && rm -f agent_config.json && python agent.py`;
    navigator.clipboard.writeText(cmd).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const filtered = devices.filter(d =>
    (d.hostname || 'Unknown').toLowerCase().includes(search.toLowerCase()) ||
    (d.ip_address || '').includes(search)
  );

  const isBusy = loading || scanning;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9', margin: 0, letterSpacing: '-0.02em' }}>Devices</h1>
          <p style={{ color: '#475569', marginTop: 4, fontSize: '0.875rem' }}>Manage network agents and endpoints</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn-secondary" onClick={handleScan} disabled={isBusy}>
            <RefreshCw size={14} style={{ marginRight: 7, ...(isBusy ? { animation: 'spin 1s linear infinite' } : {}) }} />
            {scanning ? 'Scanning…' : 'Detect'}
          </button>
          <button className="btn-primary" onClick={generateToken}>
            <Plus size={14} style={{ marginRight: 7 }} />
            Enroll Device
          </button>
        </div>
      </div>

      {/* Enrollment panel */}
      {enrollToken && (
        <div className="enroll-panel">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <h4 style={{ margin: 0, color: '#60a5fa', fontWeight: 600, fontSize: '0.95rem' }}>
              Device Enrollment Token
            </h4>
            <button onClick={() => setEnrollToken('')} style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', fontSize: '0.8rem' }}>
              ✕ Dismiss
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <span style={{ color: '#64748b', fontSize: '0.8rem' }}>Token:</span>
            <span className="token-display">{enrollToken}</span>
          </div>

          <p style={{ color: '#475569', fontSize: '0.8rem', margin: '0 0 8px', fontWeight: 500 }}>
            Run on the target Linux machine:
          </p>
          <div style={{ position: 'relative' }}>
            <div className="code-block">
              {`export ENROLLMENT_TOKEN="${enrollToken}" && export SERVER_URL="http://127.0.0.1:8002" && cd /home/sidd/SIEM/agents/linux && rm -f agent_config.json && python agent.py`}
            </div>
            <button
              onClick={copyCmd}
              style={{
                position: 'absolute', top: 10, right: 10,
                background: copied ? 'rgba(34,197,94,0.15)' : 'rgba(30,37,53,0.9)',
                border: `1px solid ${copied ? 'rgba(34,197,94,0.3)' : 'var(--color-dark-border)'}`,
                borderRadius: 7, padding: '5px 10px', cursor: 'pointer',
                color: copied ? '#4ade80' : '#64748b', fontSize: '0.75rem',
                display: 'flex', alignItems: 'center', gap: 5,
              }}
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        {/* Toolbar */}
        <div style={{
          padding: '14px 20px',
          borderBottom: '1px solid var(--color-dark-border)',
          display: 'flex', alignItems: 'center', gap: 12,
        }}>
          <div style={{ position: 'relative', flex: 1, maxWidth: 380 }}>
            <Search size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#334155' }} />
            <input
              className="input-field"
              style={{ paddingLeft: 36 }}
              placeholder="Search hostname or IP…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <span style={{ marginLeft: 'auto', color: '#334155', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
            {filtered.length} device{filtered.length !== 1 ? 's' : ''}
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Device</th>
                <th>IP Address</th>
                <th>OS</th>
                <th>Status</th>
                <th>Last Seen</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {isBusy && devices.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', color: '#334155', padding: '40px 0' }}>
                    <RefreshCw size={18} style={{ display: 'inline', marginRight: 8, animation: 'spin 1s linear infinite' }} />
                    Loading devices…
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', color: '#334155', padding: '48px 0' }}>
                    <Server size={24} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.3 }} />
                    No devices found
                  </td>
                </tr>
              ) : filtered.map((device, idx) => (
                <tr key={device.device_id || device.mac_address || idx}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{
                        width: 32, height: 32, borderRadius: 8,
                        background: 'rgba(59,130,246,0.08)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                      }}>
                        <Server size={15} color="#60a5fa" />
                      </div>
                      <div>
                        <p style={{ margin: 0, color: '#e2e8f0', fontWeight: 500, fontSize: '0.875rem' }}>
                          {device.hostname || 'Unknown'}
                        </p>
                        {device.mac_address && (
                          <p style={{ margin: 0, color: '#334155', fontSize: '0.72rem' }}>
                            {device.mac_address}
                          </p>
                        )}
                      </div>
                    </div>
                  </td>
                  <td style={{ color: '#64748b', fontFamily: 'monospace', fontSize: '0.82rem' }}>
                    {device.ip_address || '—'}
                  </td>
                  <td>
                    <span style={{
                      background: 'rgba(30,37,53,0.6)', color: '#94a3b8',
                      padding: '3px 9px', borderRadius: 6, fontSize: '0.75rem', fontWeight: 500,
                      textTransform: 'capitalize',
                    }}>
                      {device.os || 'unknown'}
                    </span>
                  </td>
                  <td><StatusBadge status={device.status} /></td>
                  <td style={{ color: '#475569', fontSize: '0.8rem', whiteSpace: 'nowrap' }}>
                    {device.last_seen ? format(new Date(device.last_seen), 'MMM d, HH:mm:ss') : '—'}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    {device.device_id ? (
                      <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                        <Link to={`/devices/${device.device_id}`} style={{
                          color: '#60a5fa', fontSize: '0.8rem', fontWeight: 500,
                          textDecoration: 'none', padding: '4px 10px',
                          background: 'rgba(59,130,246,0.08)', borderRadius: 6,
                          border: '1px solid rgba(59,130,246,0.15)',
                        }}>
                          View
                        </Link>
                        {device.status !== 'isolated' && (
                          <button style={{
                            color: '#f87171', fontSize: '0.8rem', fontWeight: 500,
                            background: 'rgba(239,68,68,0.06)', borderRadius: 6,
                            border: '1px solid rgba(239,68,68,0.15)',
                            padding: '4px 10px', cursor: 'pointer',
                          }}>
                            Isolate
                          </button>
                        )}
                      </div>
                    ) : (
                      <span style={{ color: '#334155', fontSize: '0.8rem' }}>Unmanaged</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

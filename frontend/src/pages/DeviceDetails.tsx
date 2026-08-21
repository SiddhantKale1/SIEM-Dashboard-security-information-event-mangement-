import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../services/api';
import { ArrowLeft, ShieldAlert, Cpu, HardDrive, Wifi, Clock } from 'lucide-react';
import { format } from 'date-fns';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const MOCK_METRICS = [
  { timestamp: '10:00', cpu_percent: 18, memory_percent: 42 },
  { timestamp: '10:05', cpu_percent: 34, memory_percent: 44 },
  { timestamp: '10:10', cpu_percent: 56, memory_percent: 46 },
  { timestamp: '10:15', cpu_percent: 28, memory_percent: 45 },
  { timestamp: '10:20', cpu_percent: 72, memory_percent: 49 },
  { timestamp: '10:25', cpu_percent: 41, memory_percent: 48 },
];

function InfoRow({ label, value }: { label: string; value?: string | null }) {
  return (
    <div style={{ padding: '12px 0', borderBottom: '1px solid rgba(30,37,53,0.6)', display: 'flex', flexDirection: 'column', gap: 3 }}>
      <span style={{ fontSize: '0.68rem', color: '#334155', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
        {label}
      </span>
      <span style={{ color: '#cbd5e1', fontSize: '0.875rem', fontFamily: label.includes('MAC') || label.includes('ID') ? 'monospace' : 'inherit' }}>
        {value || '—'}
      </span>
    </div>
  );
}

export default function DeviceDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [device, setDevice]   = useState<any>(null);
  const [metrics, setMetrics] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const devRes = await api.get(`/devices/${id}`);
        setDevice(devRes.data);
        try {
          const metRes = await api.get(`/devices/${id}/metrics`);
          setMetrics(metRes.data.length ? metRes.data : MOCK_METRICS);
        } catch { setMetrics(MOCK_METRICS); }
      } catch (err) { console.error(err); }
      finally { setLoading(false); }
    })();
  }, [id]);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200, color: '#475569' }}>
      Loading device…
    </div>
  );

  if (!device) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200, color: '#475569' }}>
      Device not found.
    </div>
  );

  const latestMetric = metrics[metrics.length - 1];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <button
          onClick={() => navigate('/devices')}
          style={{
            width: 36, height: 36, borderRadius: 10, flexShrink: 0,
            background: 'rgba(20,26,38,0.9)', border: '1px solid var(--color-dark-border)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer', color: '#64748b', transition: 'all 0.15s',
          }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = '#cbd5e1'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#64748b'; }}
        >
          <ArrowLeft size={16} />
        </button>

        <div style={{ flex: 1 }}>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#f1f5f9', margin: 0, letterSpacing: '-0.02em' }}>
            {device.hostname || 'Unknown Device'}
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 4 }}>
            <span className={`status-dot ${device.status}`} />
            <span style={{ color: '#475569', fontSize: '0.82rem' }}>
              {device.ip_address || 'No IP'} · {device.os || 'Unknown OS'}
            </span>
          </div>
        </div>

        <div>
          {device.status === 'online' && (
            <button className="btn-danger">
              <ShieldAlert size={14} style={{ marginRight: 7 }} />
              Isolate Device
            </button>
          )}
          {device.status === 'isolated' && (
            <button className="btn-primary">
              Restore Access
            </button>
          )}
        </div>
      </div>

      {/* Live metric tiles */}
      {latestMetric && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 14 }}>
          {[
            { label: 'CPU Usage',    value: `${latestMetric.cpu_percent ?? '—'}%`,    icon: Cpu,      color: '#60a5fa' },
            { label: 'Memory',       value: `${latestMetric.memory_percent ?? '—'}%`, icon: HardDrive, color: '#a78bfa' },
            { label: 'Network',      value: 'Online',                                  icon: Wifi,      color: '#4ade80' },
            { label: 'Last Seen',    value: device.last_seen ? format(new Date(device.last_seen), 'HH:mm:ss') : '—', icon: Clock, color: '#fb923c' },
          ].map((tile, i) => (
            <div key={i} className="stat-card" style={{ padding: '16px 18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <tile.icon size={14} color={tile.color} />
                <span style={{ fontSize: '0.7rem', color: '#334155', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em' }}>
                  {tile.label}
                </span>
              </div>
              <p style={{ margin: 0, fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9', letterSpacing: '-0.02em' }}>
                {tile.value}
              </p>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 20 }}>

        {/* Device info */}
        <div className="glass-panel" style={{ padding: '20px 20px 4px' }}>
          <p style={{ margin: '0 0 4px', fontSize: '0.7rem', fontWeight: 700, color: '#334155', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            Device Info
          </p>
          <InfoRow label="Status"        value={device.status} />
          <InfoRow label="Device ID"     value={device.device_id} />
          <InfoRow label="MAC Address"   value={device.mac_address} />
          <InfoRow label="OS Version"    value={device.os_version} />
          <InfoRow label="Agent Version" value={device.agent_version} />
          <InfoRow label="Enrolled"      value={device.enrolled_at ? format(new Date(device.enrolled_at), 'MMM d, yyyy') : undefined} />
        </div>

        {/* CPU & memory chart */}
        <div className="glass-panel" style={{ padding: 24 }}>
          <h3 style={{ margin: '0 0 20px', fontSize: '0.95rem', fontWeight: 600, color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Cpu size={15} color="#3b82f6" />
            CPU & Memory Usage
          </h3>
          <div style={{ height: 220 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={metrics} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradCpu" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%"   stopColor="#3b82f6" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#3b82f6" stopOpacity={0}   />
                  </linearGradient>
                  <linearGradient id="gradMem" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%"   stopColor="#8b5cf6" stopOpacity={0.15} />
                    <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0}    />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="2 4" stroke="rgba(30,37,53,0.8)" vertical={false} />
                <XAxis dataKey="timestamp" stroke="transparent" tick={{ fill: '#334155', fontSize: 11 }} tickLine={false} axisLine={false} />
                <YAxis stroke="transparent" tick={{ fill: '#334155', fontSize: 11 }} tickLine={false} axisLine={false} domain={[0, 100]} unit="%" />
                <Tooltip
                  contentStyle={{ background: '#0e1219', border: '1px solid #1e2535', borderRadius: 10, color: '#e2e8f0', fontSize: 12 }}
                  cursor={{ stroke: 'rgba(59,130,246,0.15)', strokeWidth: 1 }}
                />
                <Legend wrapperStyle={{ fontSize: '0.78rem', color: '#475569', paddingTop: 12 }} />
                <Area type="monotone" dataKey="cpu_percent"    name="CPU %"    stroke="#3b82f6" strokeWidth={2} fill="url(#gradCpu)" dot={false} activeDot={{ r: 4, fill: '#3b82f6' }} />
                <Area type="monotone" dataKey="memory_percent" name="Memory %" stroke="#8b5cf6" strokeWidth={2} fill="url(#gradMem)" dot={false} activeDot={{ r: 4, fill: '#8b5cf6' }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}

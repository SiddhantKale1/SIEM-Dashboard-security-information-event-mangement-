import { useState, useEffect } from 'react';
import { useDevices } from '../context/DeviceContext';
import { Server, Wifi, WifiOff, TrendingUp } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function Dashboard() {
  const { devices, fetchDevices } = useDevices();
  const [logVolume] = useState([
    { time: '00:00', count: 42  },
    { time: '03:00', count: 18  },
    { time: '06:00', count: 95  },
    { time: '09:00', count: 320 },
    { time: '12:00', count: 480 },
    { time: '15:00', count: 390 },
    { time: '18:00', count: 210 },
    { time: '21:00', count: 140 },
  ]);

  useEffect(() => {
    fetchDevices(false);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const total    = devices.length;
  const online   = devices.filter(d => d.status === 'online').length;
  const isolated = devices.filter(d => d.status === 'isolated').length;
  const offline  = devices.filter(d => d.status !== 'online' && d.status !== 'isolated').length;

  const stats = [
    {
      label: 'Total Devices', value: total,
      icon: Server, iconBg: 'rgba(59,130,246,0.12)', iconColor: '#60a5fa',
      glow: 'rgba(59,130,246,0.08)',
    },
    {
      label: 'Online', value: online,
      icon: Wifi, iconBg: 'rgba(34,197,94,0.12)', iconColor: '#4ade80',
      glow: 'rgba(34,197,94,0.06)',
    },
    {
      label: 'Offline', value: offline,
      icon: WifiOff, iconBg: 'rgba(100,116,139,0.12)', iconColor: '#94a3b8',
      glow: 'rgba(100,116,139,0.04)',
    },
    {
      label: 'Isolated', value: isolated,
      icon: WifiOff, iconBg: 'rgba(239,68,68,0.12)', iconColor: '#f87171',
      glow: 'rgba(239,68,68,0.05)',
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* Header */}
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9', margin: 0, letterSpacing: '-0.02em' }}>
          Overview
        </h1>
        <p style={{ color: '#475569', marginTop: 4, fontSize: '0.875rem' }}>
          Network and agent health at a glance
        </p>
      </div>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
        {stats.map((s, i) => (
          <div key={i} className="stat-card" style={{ boxShadow: `0 4px 20px ${s.glow}, 0 0 0 1px var(--color-dark-border)` }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div>
                <p style={{ fontSize: '0.75rem', color: '#475569', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', margin: 0 }}>
                  {s.label}
                </p>
                <p style={{ fontSize: '2.25rem', fontWeight: 800, color: '#f1f5f9', margin: '8px 0 0', lineHeight: 1, letterSpacing: '-0.03em' }}>
                  {s.value}
                </p>
              </div>
              <div style={{
                width: 40, height: 40, borderRadius: 10,
                background: s.iconBg,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
              }}>
                <s.icon size={18} color={s.iconColor} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Log volume chart */}
      <div className="glass-panel" style={{ padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
          <TrendingUp size={16} color="#3b82f6" />
          <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, color: '#e2e8f0' }}>
            Log Volume — Last 24 Hours
          </h3>
        </div>
        <div style={{ height: 240 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={logVolume} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
              <defs>
                <linearGradient id="gradCount" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%"   stopColor="#3b82f6" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#3b82f6" stopOpacity={0}    />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="2 4" stroke="rgba(30,37,53,0.8)" vertical={false} />
              <XAxis dataKey="time" stroke="transparent" tick={{ fill: '#334155', fontSize: 11 }} tickLine={false} axisLine={false} />
              <YAxis stroke="transparent" tick={{ fill: '#334155', fontSize: 11 }} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{ background: '#0e1219', border: '1px solid #1e2535', borderRadius: 10, color: '#e2e8f0', fontSize: 12 }}
                itemStyle={{ color: '#60a5fa' }}
                cursor={{ stroke: 'rgba(59,130,246,0.2)', strokeWidth: 1 }}
              />
              <Area
                type="monotone" dataKey="count" name="Events"
                stroke="#3b82f6" strokeWidth={2}
                fillOpacity={1} fill="url(#gradCount)"
                dot={false} activeDot={{ r: 4, fill: '#3b82f6', stroke: '#0e1219', strokeWidth: 2 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent devices mini-list */}
      {devices.length > 0 && (
        <div className="glass-panel" style={{ padding: '0' }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--color-dark-border)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Server size={15} color="#3b82f6" />
            <h3 style={{ margin: 0, fontSize: '0.875rem', fontWeight: 600, color: '#e2e8f0' }}>
              Recent Devices
            </h3>
          </div>
          <div>
            {devices.slice(0, 5).map((d, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '12px 20px',
                borderBottom: i < Math.min(devices.length, 5) - 1 ? '1px solid rgba(30,37,53,0.5)' : 'none',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span className={`status-dot ${d.status || 'offline'}`} />
                  <span style={{ color: '#cbd5e1', fontSize: '0.875rem', fontWeight: 500 }}>{d.hostname || 'Unknown'}</span>
                  <span style={{ color: '#334155', fontSize: '0.8rem' }}>{d.ip_address || ''}</span>
                </div>
                <span className={`badge badge-${d.status || 'offline'}`}>{d.status || 'offline'}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

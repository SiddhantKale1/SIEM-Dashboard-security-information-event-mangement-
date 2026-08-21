import { useState, useEffect } from 'react';
import { useDevices } from '../context/DeviceContext';
import { Activity, Server, AlertCircle, ShieldCheck } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function Dashboard() {
  const { devices, fetchDevices } = useDevices();
  const [logVolume, setLogVolume] = useState<any[]>([]);

  useEffect(() => {
    fetchDevices(false); // uses cache if fresh — no duplicate API call
    setLogVolume([
      { time: '00:00', count: 120 },
      { time: '04:00', count: 80 },
      { time: '08:00', count: 450 },
      { time: '12:00', count: 600 },
      { time: '16:00', count: 320 },
      { time: '20:00', count: 190 },
    ]);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const statCards = [
    { title: 'Total Devices',    value: devices.length,                                              icon: Server,      color: 'text-brand-primary' },
    { title: 'Online',           value: devices.filter(d => d.status === 'online').length,           icon: Activity,    color: 'text-green-500' },
    { title: 'Offline/Isolated', value: devices.filter(d => d.status === 'offline' || d.status === 'isolated').length, icon: AlertCircle, color: 'text-red-500' },
    { title: 'Logs Today',       value: 1245,                                                        icon: ShieldCheck, color: 'text-brand-secondary' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Overview</h1>
        <p className="text-gray-400 mt-1">Network and agent health status</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statCards.map((stat, idx) => (
          <div key={idx} className="glass-panel p-6 flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm font-medium">{stat.title}</p>
              <h3 className="text-3xl font-bold text-white mt-1">{stat.value}</h3>
            </div>
            <div className={`p-3 rounded-lg bg-[var(--color-dark-bg)] ${stat.color}`}>
              <stat.icon className="w-6 h-6" />
            </div>
          </div>
        ))}
      </div>

      <div className="glass-panel p-6">
        <h3 className="text-lg font-semibold text-white mb-6">Log Volume (Last 24 Hours)</h3>
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={logVolume} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="var(--color-brand-primary)" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="var(--color-brand-primary)" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#2e3340" vertical={false} />
              <XAxis dataKey="time" stroke="#6b7280" tick={{ fill: '#6b7280', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis stroke="#6b7280" tick={{ fill: '#6b7280', fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1a1d24', borderColor: '#2e3340', color: '#fff' }}
                itemStyle={{ color: '#3b82f6' }}
              />
              <Area type="monotone" dataKey="count" stroke="var(--color-brand-primary)" strokeWidth={3} fillOpacity={1} fill="url(#colorCount)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

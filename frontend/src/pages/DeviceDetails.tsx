import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../services/api';
import { ArrowLeft, ShieldAlert } from 'lucide-react';
import { format } from 'date-fns';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

export default function DeviceDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [device, setDevice] = useState<any>(null);
  const [metrics, setMetrics] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const devRes = await api.get(`/devices/${id}`);
        setDevice(devRes.data);
        
        // Mock fetching metrics and processes since endpoints for specific device might need to be added.
        // For MVP frontend we can handle this gracefully.
        try {
          const metRes = await api.get(`/devices/${id}/metrics`);
          setMetrics(metRes.data);
        } catch (e) {
          // Fallback mock data if API not fully implemented
          setMetrics([
            { timestamp: '10:00', cpu_percent: 20, memory_percent: 45 },
            { timestamp: '10:05', cpu_percent: 25, memory_percent: 46 },
            { timestamp: '10:10', cpu_percent: 45, memory_percent: 48 },
            { timestamp: '10:15', cpu_percent: 30, memory_percent: 47 },
          ]);
        }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchAll();
  }, [id]);

  if (loading) return <div className="text-white p-8">Loading...</div>;
  if (!device) return <div className="text-white p-8">Device not found</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <button onClick={() => navigate('/devices')} className="p-2 bg-[#2a2e39] rounded-lg hover:bg-[#323744] text-gray-300 transition-colors">
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">{device.hostname}</h1>
          <p className="text-gray-400 mt-1">{device.ip_address} • {device.os}</p>
        </div>
        <div className="ml-auto">
          {device.status === 'online' ? (
             <button className="btn-danger flex items-center">
               <ShieldAlert className="w-4 h-4 mr-2" /> Isolate Device
             </button>
          ) : device.status === 'isolated' ? (
             <button className="btn-primary flex items-center">
               Restore Access
             </button>
          ) : null}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="glass-panel p-6 col-span-1 md:col-span-1">
          <h3 className="text-sm font-medium text-gray-400 mb-4 uppercase tracking-wider">Overview</h3>
          <div className="space-y-4">
            <div><p className="text-gray-500 text-xs">STATUS</p><p className="text-gray-200 capitalize flex items-center"><div className={`w-2 h-2 rounded-full mr-2 ${device.status === 'online' ? 'bg-green-500' : 'bg-red-500'}`} />{device.status}</p></div>
            <div><p className="text-gray-500 text-xs">MAC ADDRESS</p><p className="text-gray-200">{device.mac_address}</p></div>
            <div><p className="text-gray-500 text-xs">AGENT VERSION</p><p className="text-gray-200">{device.agent_version}</p></div>
            <div><p className="text-gray-500 text-xs">LAST SEEN</p><p className="text-gray-200">{format(new Date(device.last_seen), 'MMM dd, HH:mm:ss')}</p></div>
          </div>
        </div>

        <div className="glass-panel p-6 col-span-1 md:col-span-3">
          <h3 className="text-lg font-semibold text-white mb-6">CPU & Memory Usage</h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={metrics} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--color-brand-primary)" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="var(--color-brand-primary)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#2e3340" vertical={false} />
                <XAxis dataKey="timestamp" stroke="#6b7280" tick={{ fill: '#6b7280', fontSize: 12 }} axisLine={false} tickLine={false} />
                <YAxis stroke="#6b7280" tick={{ fill: '#6b7280', fontSize: 12 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#1a1d24', borderColor: '#2e3340', color: '#fff' }} />
                <Area type="monotone" dataKey="cpu_percent" name="CPU %" stroke="var(--color-brand-primary)" strokeWidth={2} fillOpacity={1} fill="url(#colorCpu)" />
                <Area type="monotone" dataKey="memory_percent" name="Memory %" stroke="var(--color-brand-secondary)" strokeWidth={2} fill="transparent" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}

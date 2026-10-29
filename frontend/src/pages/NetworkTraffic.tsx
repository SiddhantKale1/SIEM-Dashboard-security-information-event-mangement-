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
    <div className="flex flex-col gap-5 max-w-[1600px] mx-auto pb-8 font-sans">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-extrabold text-[#111827] tracking-tight">
              Network Traffic &amp; Active Systems
            </h1>
            <span className="text-xs font-bold px-2.5 py-0.5 rounded-full bg-[#e0f2fe] text-[#0284c7]">
              SUBNET: {trafficData.network?.subnet || '—'}
            </span>
          </div>
          <p className="text-xs text-[#6b7280] mt-1 font-medium">
            Real-time active subnet monitoring, ARP sweeps, and automated session auditing
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button 
            type="button"
            onClick={() => loadData(true)}
            disabled={scanning}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-[#111827] text-white rounded-xl text-xs font-semibold hover:bg-black transition-all shadow-2xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin text-[#82c341]' : 'text-[#82c341]'}`} />
            <span>{scanning ? 'Sweeping Subnet ARP...' : 'Scan Active Subnet'}</span>
          </button>
        </div>
      </div>

      {/* Top 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
          <div className="text-[11px] text-[#9ca3af] font-semibold uppercase tracking-wider">Active Subnet</div>
          <div className="text-xl font-mono font-extrabold text-[#111827] mt-1">
            {trafficData.network?.subnet || '192.168.1.0/24'}
          </div>
          <div className="text-xs text-[#6b7280] mt-1">
            Gateway: {trafficData.network?.gateway || '192.168.1.1'}
          </div>
        </div>

        <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
          <div className="text-[11px] text-[#9ca3af] font-semibold uppercase tracking-wider">Live Connected Nodes</div>
          <div className="text-xl font-extrabold text-[#111827] mt-1">
            {trafficData.active_devices_count} <span className="text-xs font-normal text-[#6b7280]">systems</span>
          </div>
          <div className="text-xs text-[#65a30d] font-semibold mt-1">
            ● Active within last 90s
          </div>
        </div>

        <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
          <div className="text-[11px] text-[#9ca3af] font-semibold uppercase tracking-wider">Throughput Volume</div>
          <div className="text-xl font-mono font-extrabold text-[#111827] mt-1 flex items-center gap-2">
            <span>TX: {formatBytes(trafficData.aggregate_tx_bytes)}</span>
          </div>
          <div className="text-xs text-[#3b82f6] font-medium mt-1">
            RX: {formatBytes(trafficData.aggregate_rx_bytes)}
          </div>
        </div>

        <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
          <div className="text-[11px] text-[#9ca3af] font-semibold uppercase tracking-wider">Connection Sessions</div>
          <div className="text-xl font-extrabold text-[#111827] mt-1">
            {trafficData.history_sessions_count} <span className="text-xs font-normal text-[#6b7280]">sessions</span>
          </div>
          <div className="text-xs text-[#6b7280] mt-1">
            Historical sessions tracked
          </div>
        </div>
      </div>

      {/* Tabs and Search Bar */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveTab('active')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
              activeTab === 'active' 
                ? 'bg-[#111827] text-white shadow-2xs' 
                : 'bg-white border border-[#e5e7eb] text-[#6b7280] hover:text-[#111827]'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Active Systems ({activeDevices.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('history')}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
              activeTab === 'history' 
                ? 'bg-[#111827] text-white shadow-2xs' 
                : 'bg-white border border-[#e5e7eb] text-[#6b7280] hover:text-[#111827]'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>Connection History ({connectionHistory.length})</span>
          </button>
        </div>

        <div className="relative w-80">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[#9ca3af]" />
          <input 
            type="text" 
            placeholder={activeTab === 'active' ? 'Search active endpoints...' : 'Search past sessions, subnets, IPs...'}
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-white border border-[#e5e7eb] rounded-xl pl-10 pr-4 py-2 text-xs font-medium text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#82c341] transition-all shadow-2xs"
          />
        </div>
      </div>

      {/* ── TAB 1: ACTIVE CURRENT NETWORK SYSTEMS ── */}
      {activeTab === 'active' && (
        <div className="bg-white rounded-[24px] p-6 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-extrabold text-[#111827]">
                Endpoints Online on {trafficData.network?.subnet || 'Active Subnet'}
              </h3>
              <p className="text-xs text-[#6b7280] mt-0.5">
                Real-time hosts actively communicating on this subnet.
              </p>
            </div>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#dcfce7] text-[#166534]">
              STRICT SUBNET FILTERING ACTIVE
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#e5e7eb] text-[#6b7280] font-mono text-[11px]">
                  <th className="py-2.5 px-3">HEALTH</th>
                  <th className="py-2.5 px-3">HOSTNAME</th>
                  <th className="py-2.5 px-3">IP ADDRESS</th>
                  <th className="py-2.5 px-3">MAC ADDRESS</th>
                  <th className="py-2.5 px-3">OPERATING SYSTEM</th>
                  <th className="py-2.5 px-3">LAST SEEN</th>
                  <th className="py-2.5 px-3 text-right">SECURITY ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#f0f2f5]">
                {filteredActiveDevices.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-xs text-[#9ca3af]">
                      No active systems currently discovered on {trafficData.network?.subnet || 'local network'}.
                    </td>
                  </tr>
                ) : (
                  filteredActiveDevices.map((dev: any) => (
                    <tr key={dev._id} className="hover:bg-[#f9fafb] transition-colors">
                      <td className="py-3 px-3">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                          dev.status === 'isolated' ? 'bg-[#fee2e2] text-[#991b1b]' : 'bg-[#dcfce7] text-[#166534]'
                        }`}>
                          {dev.status === 'isolated' ? 'ISOLATED' : dev.current_network_state || 'ONLINE'}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-bold text-[#111827]">
                        {dev.hostname || 'Unknown Endpoint'}
                      </td>
                      <td className="py-3 px-3 font-mono text-[#0284c7]">
                        {dev.ip_address}
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[#6b7280]">
                        {dev.mac_address}
                      </td>
                      <td className="py-3 px-3 capitalize text-[#374151]">
                        {dev.os} {dev.os_version ? `(${dev.os_version.slice(0, 10)})` : ''}
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[#9ca3af]">
                        {dev.last_seen ? new Date(dev.last_seen).toLocaleTimeString() : 'Just now'}
                      </td>
                      <td className="py-3 px-3 text-right">
                        {dev.status === 'isolated' ? (
                          <button
                            type="button"
                            onClick={() => handleRestore(dev.device_id)}
                            className="px-2.5 py-1 bg-[#dcfce7] text-[#166534] rounded-lg text-xs font-bold hover:bg-[#bbf7d0] transition-colors inline-flex items-center gap-1"
                          >
                            <Unlock className="w-3 h-3" />
                            <span>Restore Access</span>
                          </button>
                        ) : dev.device_id ? (
                          <button
                            type="button"
                            onClick={() => handleIsolate(dev.device_id)}
                            className="px-2.5 py-1 bg-[#fee2e2] text-[#991b1b] rounded-lg text-xs font-bold hover:bg-[#fecaca] transition-colors inline-flex items-center gap-1"
                          >
                            <Lock className="w-3 h-3" />
                            <span>Isolate Device</span>
                          </button>
                        ) : (
                          <span className="text-xs text-[#9ca3af]">Unmanaged ARP</span>
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
        <div className="bg-white rounded-[24px] p-6 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-extrabold text-[#111827]">
                Endpoint Connection &amp; Session History ({connectionHistory.length})
              </h3>
              <p className="text-xs text-[#6b7280] mt-0.5">
                Complete chronological audit of past network switches, disconnect timestamps, and log activity.
              </p>
            </div>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#f3f4f6] text-[#374151]">
              AUDIT TRAIL
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#e5e7eb] text-[#6b7280] font-mono text-[11px]">
                  <th className="py-2.5 px-3">SESSION STATUS</th>
                  <th className="py-2.5 px-3">HOSTNAME</th>
                  <th className="py-2.5 px-3">IP &amp; SUBNET</th>
                  <th className="py-2.5 px-3">CONNECTED AT</th>
                  <th className="py-2.5 px-3">DISCONNECTED</th>
                  <th className="py-2.5 px-3">DURATION</th>
                  <th className="py-2.5 px-3">LOGS PROCESSED</th>
                  <th className="py-2.5 px-3">REASON</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#f0f2f5]">
                {filteredHistory.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-xs text-[#9ca3af]">
                      No connection history sessions recorded yet.
                    </td>
                  </tr>
                ) : (
                  filteredHistory.map((sess: any) => (
                    <tr key={sess._id} className="hover:bg-[#f9fafb] transition-colors">
                      <td className="py-3 px-3">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                          sess.status === 'active' ? 'bg-[#dcfce7] text-[#166534]' : 'bg-[#f3f4f6] text-[#4b5563]'
                        }`}>
                          {sess.status === 'active' ? 'ACTIVE' : 'CLOSED'}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-bold text-[#111827]">
                        {sess.hostname}
                      </td>
                      <td className="py-3 px-3 font-mono">
                        <div className="text-[#0284c7] font-semibold">{sess.ip_address}</div>
                        <div className="text-[10px] text-[#9ca3af]">{sess.subnet}</div>
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[#6b7280]">
                        {new Date(sess.connected_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[#6b7280]">
                        {sess.disconnected_at ? new Date(sess.disconnected_at).toLocaleString() : 'Currently Active'}
                      </td>
                      <td className="py-3 px-3 font-mono text-[#111827]">
                        {sess.duration_seconds ? `${Math.floor(sess.duration_seconds / 60)}m ${sess.duration_seconds % 60}s` : 'Ongoing'}
                      </td>
                      <td className="py-3 px-3 font-mono text-[#166534] font-semibold">
                        {sess.logs_sent || 0} events
                      </td>
                      <td className="py-3 px-3">
                        <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-[#f4f5f7] text-[#374151]">
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

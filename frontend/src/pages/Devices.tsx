import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useDevices } from '../context/DeviceContext';
import api from '../services/api';
import { Search, Plus, Monitor, RefreshCw } from 'lucide-react';
import { format } from 'date-fns';

export default function Devices() {
  // Global device cache — persists across navigation without re-fetching
  const { devices, loading, fetchDevices, invalidate } = useDevices();

  const [search, setSearch] = useState('');
  const [enrollToken, setEnrollToken] = useState('');
  const [scanning, setScanning] = useState(false);

  // On first mount, load devices from cache (no API call if cache is fresh)
  useEffect(() => {
    fetchDevices(false);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleScan = async () => {
    setScanning(true);
    await fetchDevices(true); // force=true bypasses cache + triggers ARP scan
    setScanning(false);
  };

  const generateToken = async () => {
    try {
      const res = await api.post('/enrollment/token');
      setEnrollToken(res.data.token);
      // Invalidate cache so after enrollment the new device shows up on next load
      invalidate();
    } catch (err) {
      console.error(err);
    }
  };

  const filtered = devices.filter(d =>
    (d.hostname || 'Unknown').toLowerCase().includes(search.toLowerCase()) ||
    (d.ip_address || '').includes(search)
  );

  const isBusy = loading || scanning;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Devices</h1>
          <p className="text-gray-400 mt-1">Manage network agents and endpoints</p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleScan}
            className="btn-secondary flex items-center"
            disabled={isBusy}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isBusy ? 'animate-spin' : ''}`} />
            {scanning ? 'Scanning...' : 'Detect Devices'}
          </button>

          <button onClick={generateToken} className="btn-primary flex items-center">
            <Plus className="w-4 h-4 mr-2" />
            Add Device
          </button>
        </div>
      </div>

      {enrollToken && (
        <div className="glass-panel p-6 border border-brand-primary/50 relative">
          <button onClick={() => setEnrollToken('')} className="absolute top-4 right-4 text-gray-400 hover:text-white">Dismiss</button>

          <h4 className="text-xl text-brand-primary font-semibold mb-2">Device Enrollment Token</h4>
          <p className="text-gray-300 text-sm mb-6">Your token is: <span className="font-mono text-white bg-black/50 px-2 py-1 rounded ml-2">{enrollToken}</span></p>

          <div className="space-y-4">
            <div>
              <p className="text-gray-400 text-sm font-medium mb-2">To enroll a Linux device, run this on the target machine:</p>
              <div className="bg-[#111318] p-4 rounded-lg flex items-center justify-between border border-[var(--color-dark-border)]">
                <code className="text-green-400 text-sm font-mono break-all">
                  export ENROLLMENT_TOKEN="{enrollToken}" && export SERVER_URL="http://127.0.0.1:8002" && cd /home/sidd/SIEM/agents/linux && rm -f agent_config.json && python agent.py
                </code>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="glass-panel overflow-hidden">
        <div className="p-4 border-b border-[var(--color-dark-border)] flex items-center gap-4">
          <div className="relative flex-1 max-w-md">
            <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              placeholder="Search hostname or IP..."
              className="input-field pl-10"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <span className="text-gray-500 text-sm ml-auto">{filtered.length} device{filtered.length !== 1 ? 's' : ''}</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-[#111318]/50 text-gray-400 text-sm border-b border-[var(--color-dark-border)]">
                <th className="px-6 py-4 font-medium">Device</th>
                <th className="px-6 py-4 font-medium">IP Address</th>
                <th className="px-6 py-4 font-medium">OS</th>
                <th className="px-6 py-4 font-medium">Status</th>
                <th className="px-6 py-4 font-medium">Last Seen</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--color-dark-border)]">
              {isBusy && devices.length === 0 ? (
                <tr><td colSpan={6} className="px-6 py-8 text-center text-gray-500">Loading devices...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={6} className="px-6 py-8 text-center text-gray-500">No devices found</td></tr>
              ) : (
                filtered.map((device, idx) => (
                  <tr key={device.device_id || device.mac_address || idx} className="hover:bg-[#2a2e39]/30 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <Monitor className="w-5 h-5 text-gray-400 mr-3" />
                        <span className="font-medium text-gray-200">{device.hostname || 'Unknown'}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-gray-400">{device.ip_address || 'N/A'}</td>
                    <td className="px-6 py-4">
                      <span className="capitalize text-gray-300 bg-[#2a2e39] px-2.5 py-1 rounded-md text-xs font-medium">
                        {device.os || 'unknown'}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <div className={`w-2 h-2 rounded-full mr-2 ${
                          device.status === 'online'     ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]' :
                          device.status === 'isolated'   ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]' :
                          device.status === 'discovered' ? 'bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]' :
                          'bg-gray-500'
                        }`} />
                        <span className="text-gray-300 capitalize text-sm">{device.status || 'unknown'}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-gray-400 text-sm">
                      {device.last_seen ? format(new Date(device.last_seen), 'MMM dd, HH:mm:ss') : 'Never'}
                    </td>
                    <td className="px-6 py-4 text-right">
                      {device.device_id ? (
                        <>
                          <Link to={`/devices/${device.device_id}`} className="text-brand-primary hover:text-blue-400 font-medium text-sm mr-4">
                            View
                          </Link>
                          {device.status !== 'isolated' && (
                            <button className="text-red-400 hover:text-red-300 font-medium text-sm">
                              Isolate
                            </button>
                          )}
                        </>
                      ) : (
                        <span className="text-gray-500 text-sm italic">Unmanaged</span>
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
  );
}

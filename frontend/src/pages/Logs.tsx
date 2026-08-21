import { useState, useEffect } from 'react';
import api from '../services/api';
import { Search, Filter, AlertTriangle, Info } from 'lucide-react';
import { format } from 'date-fns';

export default function Logs() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res = await api.get('/logs');
        setLogs(res.data);
      } catch (err) {
        console.error(err);
        // Fallback mock if API not completely wired up yet
        setLogs([
          { _id: '1', timestamp: new Date().toISOString(), device_id: 'device-123', hostname: 'TEST-DESKTOP', source: 'Security', event_id: 4624, event_type: 'authentication', severity: 'information', message: 'An account was successfully logged on.' },
          { _id: '2', timestamp: new Date().toISOString(), device_id: 'device-456', hostname: 'LINUX-SERVER', source: 'sshd', event_id: 'sshd', event_type: 'system', severity: 'error', message: 'Failed password for invalid user root from 192.168.1.5' },
        ]);
      } finally {
        setLoading(false);
      }
    };
    fetchLogs();
  }, []);

  const filtered = logs.filter(l => 
    l.hostname?.toLowerCase().includes(search.toLowerCase()) || 
    l.message?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6 flex flex-col h-full">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Log Explorer</h1>
        <p className="text-gray-400 mt-1">Search and filter centralized device logs</p>
      </div>

      <div className="glass-panel flex-1 flex flex-col min-h-0">
        <div className="p-4 border-b border-[var(--color-dark-border)] flex items-center gap-4">
          <div className="relative flex-1 max-w-xl">
            <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500" />
            <input 
              type="text" 
              placeholder="Search logs by keyword, device, or IP..." 
              className="input-field pl-10"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <button className="btn-secondary flex items-center">
            <Filter className="w-4 h-4 mr-2" /> Filters
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          <table className="w-full text-left border-collapse">
            <thead className="sticky top-0 bg-[#111318] shadow-md z-10">
              <tr className="text-gray-400 text-sm border-b border-[var(--color-dark-border)]">
                <th className="px-6 py-4 font-medium">Timestamp</th>
                <th className="px-6 py-4 font-medium">Device</th>
                <th className="px-6 py-4 font-medium">Source</th>
                <th className="px-6 py-4 font-medium">Event ID</th>
                <th className="px-6 py-4 font-medium">Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--color-dark-border)]">
              {loading ? (
                <tr><td colSpan={5} className="px-6 py-8 text-center text-gray-500">Loading logs...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={5} className="px-6 py-8 text-center text-gray-500">No logs found</td></tr>
              ) : (
                filtered.map((log) => (
                  <tr key={log._id} className="hover:bg-[#2a2e39]/30 transition-colors group cursor-pointer">
                    <td className="px-6 py-4 text-gray-400 text-sm whitespace-nowrap">
                      {format(new Date(log.timestamp), 'MMM dd, HH:mm:ss')}
                    </td>
                    <td className="px-6 py-4">
                      <span className="font-medium text-gray-200">{log.hostname}</span>
                    </td>
                    <td className="px-6 py-4 text-gray-400 text-sm">{log.source}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        {log.severity === 'error' ? <AlertTriangle className="w-4 h-4 text-red-500 mr-2" /> : <Info className="w-4 h-4 text-blue-400 mr-2" />}
                        <span className="text-gray-300">{log.event_id}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-gray-300 text-sm truncate max-w-md">
                      {log.message}
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

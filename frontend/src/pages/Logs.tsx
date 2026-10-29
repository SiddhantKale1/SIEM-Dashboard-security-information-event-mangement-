import { useState, useEffect } from 'react';
import api from '../services/api';
import { Search, Terminal, RefreshCw, Radio, X } from 'lucide-react';
import { format } from 'date-fns';

function SeverityBadge({ severity }: { severity: string }) {
  if (severity === 'error')   return <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#fee2e2] text-[#991b1b] uppercase">ERROR</span>;
  if (severity === 'warning') return <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#fef9c3] text-[#854d0e] uppercase">WARNING</span>;
  return <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#dcfce7] text-[#166534] uppercase">INFO</span>;
}

export default function Logs() {
  const [logs, setLogs]       = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(false);
  const [search, setSearch]   = useState('');
  const [filter, setFilter]   = useState<'all' | 'error' | 'warning' | 'information'>('all');
  const [page, setPage]       = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalLogs, setTotalLogs]   = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedLog, setSelectedLog] = useState<any | null>(null);

  const fetchLogs = async (p = page, fil = filter, q = search) => {
    setLoading(true);
    setApiError(false);
    try {
      const params: Record<string, any> = { page: p, limit: 50 };
      if (fil !== 'all') {
        params.severity = fil;
      }
      if (q.trim()) params.search = q.trim();

      const r = await api.get('/logs', { params });
      setLogs(r.data.logs ?? r.data);
      setTotalPages(r.data.pages ?? 1);
      setTotalLogs(r.data.total ?? r.data.length);
    } catch {
      setApiError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { 
    fetchLogs(1, filter); 
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchLogs(page, filter, search);
    }, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh, page, filter, search]);

  const handleFilterChange = (f: typeof filter) => {
    setFilter(f);
    setPage(1);
    fetchLogs(1, f, search);
  };

  const handleSearchSubmit = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      setPage(1);
      fetchLogs(1, filter, search);
    }
  };

  const filterTabs: { key: typeof filter; label: string }[] = [
    { key: 'all',         label: `All Logs` },
    { key: 'error',       label: `Errors` },
    { key: 'warning',     label: `Warnings` },
    { key: 'information', label: `Info` },
  ];

  return (
    <div className="flex flex-col gap-5 max-w-[1600px] mx-auto pb-8 font-sans">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-extrabold text-[#111827] tracking-tight">
              Centralized Security Event &amp; Log Stream
            </h1>
            <span className="text-xs font-bold px-2.5 py-0.5 rounded-full bg-[#f3f4f6] text-[#374151]">
              {totalLogs.toLocaleString()} EVENTS RECORDED
            </span>
          </div>
          <p className="text-xs text-[#6b7280] mt-1 font-medium">
            Real-time security telemetry, authentication audits, and system event stream across all enrolled endpoints
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button 
            type="button"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-bold transition-all ${
              autoRefresh 
                ? 'bg-[#dcfce7] text-[#166534] border border-[#bbf7d0]' 
                : 'bg-white border border-[#e5e7eb] text-[#6b7280]'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>{autoRefresh ? 'Live Auto-Stream: ON' : 'Live Stream: PAUSED'}</span>
          </button>

          <button 
            type="button"
            onClick={() => fetchLogs(page, filter, search)}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#e5e7eb] rounded-xl text-xs font-semibold text-[#111827] hover:bg-[#f9fafb] transition-all shadow-2xs"
          >
            <RefreshCw className="w-3.5 h-3.5 text-[#6b7280]" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Toolbar */}
      <div className="bg-white rounded-[24px] p-4 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex items-center justify-between gap-4 flex-wrap">
        <div className="relative flex-1 min-w-[280px]">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[#9ca3af]" />
          <input
            className="w-full bg-[#f9fafb] border border-[#e5e7eb] rounded-xl pl-10 pr-4 py-2 text-xs font-medium text-[#111827] placeholder-[#9ca3af] focus:bg-white focus:outline-none focus:border-[#82c341] transition-all"
            placeholder="Search security events (e.g. login, sudo, hostname, event ID)..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            onKeyDown={handleSearchSubmit}
          />
        </div>

        {/* Filter tabs */}
        <div className="flex items-center bg-[#f4f5f7] rounded-xl p-1 gap-1">
          {filterTabs.map(t => (
            <button
              key={t.key}
              type="button"
              onClick={() => handleFilterChange(t.key)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                filter === t.key 
                  ? 'bg-white text-[#111827] shadow-xs' 
                  : 'text-[#6b7280] hover:text-[#111827]'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <span className="text-xs font-mono text-[#9ca3af]">
          Showing {logs.length} of {totalLogs}
        </span>
      </div>

      {apiError && (
        <div className="bg-[#fef2f2] border border-[#fecaca] rounded-2xl p-4 text-xs font-semibold text-[#991b1b]">
          Failed to fetch logs from backend API. Please verify backend service status.
        </div>
      )}

      {/* Logs Table */}
      <div className="bg-white rounded-[24px] border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#e5e7eb] text-[#6b7280] font-mono text-[11px] bg-[#fcfcfd]">
                <th className="py-3 px-4 w-28">STATUS</th>
                <th className="py-3 px-4 w-40">CATEGORY</th>
                <th className="py-3 px-4">EVENT SUMMARY</th>
                <th className="py-3 px-4 w-36">ENDPOINT</th>
                <th className="py-3 px-4 w-28 text-right">TIME</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#f0f2f5]">
              {loading && logs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-xs text-[#9ca3af]">
                    Streaming real-time security events from endpoints...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-xs text-[#9ca3af]">
                    No events match current filter.
                  </td>
                </tr>
              ) : (
                logs.map((log: any) => (
                  <tr 
                    key={log._id}
                    onClick={() => setSelectedLog(log)}
                    className="hover:bg-[#f9fafb] cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4">
                      <SeverityBadge severity={log.severity} />
                    </td>
                    <td className="py-3 px-4">
                      <span className="inline-block px-2 py-0.5 rounded-md text-[11px] font-bold bg-[#f4f5f7] text-[#374151]">
                        {log.category || 'System Event'}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-bold text-[#111827]">
                        {log.friendly_summary || log.message || '—'}
                      </div>
                      {log.friendly_summary && log.friendly_summary !== log.message && (
                        <div className="text-[11px] text-[#6b7280] font-mono mt-0.5 truncate max-w-xl">
                          Technical: {log.message}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4 font-bold text-[#0284c7]">
                      {log.hostname || '—'}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-[#9ca3af] text-right">
                      {log.timestamp ? format(new Date(log.timestamp), 'HH:mm:ss') : '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="p-4 border-t border-[#f0f2f5] flex items-center justify-between bg-[#fcfcfd]">
          <span className="text-xs text-[#6b7280]">
            Page {page} of {totalPages}
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => { const p = Math.max(1, page - 1); setPage(p); fetchLogs(p, filter, search); }}
              disabled={page <= 1}
              className="px-3 py-1 bg-white border border-[#e5e7eb] rounded-lg text-xs font-semibold text-[#111827] hover:bg-[#f9fafb] disabled:opacity-50"
            >
              Previous
            </button>
            <button
              type="button"
              onClick={() => { const p = Math.min(totalPages, page + 1); setPage(p); fetchLogs(p, filter, search); }}
              disabled={page >= totalPages}
              className="px-3 py-1 bg-white border border-[#e5e7eb] rounded-lg text-xs font-semibold text-[#111827] hover:bg-[#f9fafb] disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Log Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-xs flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-[28px] border border-[#eaecf0] shadow-xl w-full max-w-2xl p-6 relative">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#f0f2f5]">
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-[#82c341]" />
                <h3 className="text-base font-extrabold text-[#111827]">
                  Endpoint Event Details
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="p-1 rounded-lg text-[#9ca3af] hover:text-[#111827]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4 text-xs">
              <div>
                <span className="text-[10px] text-[#9ca3af] uppercase font-bold block mb-1">ENDPOINT</span>
                <span className="font-extrabold text-[#111827]">{selectedLog.hostname}</span>
              </div>
              <div>
                <span className="text-[10px] text-[#9ca3af] uppercase font-bold block mb-1">CATEGORY</span>
                <span className="font-bold text-[#0284c7]">{selectedLog.category || 'General'}</span>
              </div>
            </div>

            <div className="mb-4">
              <span className="text-[10px] text-[#9ca3af] uppercase font-bold block mb-1">EVENT SUMMARY</span>
              <div className="bg-[#f9fafb] border border-[#e5e7eb] rounded-xl p-3 text-xs font-bold text-[#111827]">
                {selectedLog.friendly_summary || selectedLog.message}
              </div>
            </div>

            <div>
              <span className="text-[10px] text-[#9ca3af] uppercase font-bold block mb-1">RAW TECHNICAL LOG</span>
              <pre className="bg-[#111827] text-white rounded-xl p-3 text-[11px] font-mono overflow-y-auto max-h-48 whitespace-pre-wrap break-all">
                {selectedLog.raw_log || selectedLog.message}
              </pre>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

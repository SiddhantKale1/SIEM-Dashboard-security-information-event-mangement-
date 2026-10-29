import { useState, useEffect } from 'react';
import api from '../services/api';
import { Search, Terminal, RefreshCw, Radio } from 'lucide-react';
import { format } from 'date-fns';

function SeverityBadge({ severity }: { severity: string }) {
  if (severity === 'error')   return <span className="neo-badge neo-badge-critical">ERROR</span>;
  if (severity === 'warning') return <span className="neo-badge neo-badge-medium">WARNING</span>;
  return <span className="neo-badge neo-badge-low">INFO</span>;
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

  const filterTabs: { key: typeof filter; label: string; color: string }[] = [
    { key: 'all',         label: `All Logs`, color: '#06b6d4' },
    { key: 'error',       label: `Errors`,   color: '#e11d48' },
    { key: 'warning',     label: `Warnings`, color: '#f59e0b' },
    { key: 'information', label: `Info`,     color: '#3b82f6' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, margin: 0, letterSpacing: '-0.03em', color: '#f8fafc' }}>
              Centralized Security Event &amp; Log Stream
            </h1>
            <span className="neo-badge neo-badge-cyan">
              {totalLogs} EVENTS RECORDED
            </span>
          </div>
          <p style={{ margin: '4px 0 0', fontSize: '0.85rem', color: '#64748b' }}>
            Real-time security telemetry, authentication audits, and system event stream across all enrolled endpoints
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button 
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`neo-btn ${autoRefresh ? 'neo-btn-emerald' : 'neo-btn-ghost'}`}
            style={{ padding: '8px 14px', fontSize: '0.8rem' }}
          >
            <Radio size={14} className={autoRefresh ? 'pulse-dot' : ''} />
            {autoRefresh ? 'Live Auto-Stream: ON' : 'Live Stream: PAUSED'}
          </button>
          <button 
            onClick={() => fetchLogs(page, filter, search)}
            className="neo-btn neo-btn-ghost"
            style={{ padding: '8px 14px', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* Bento Toolbar */}
      <div className="bento-card" style={{ padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: 280 }}>
          <Search size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
          <input
            style={{
              width: '100%',
              background: '#070a11',
              border: '2px solid #1e293b',
              borderRadius: 8,
              padding: '8px 12px 8px 36px',
              color: '#f8fafc',
              fontSize: '0.82rem',
              outline: 'none',
              fontFamily: 'inherit'
            }}
            placeholder="Search security events (e.g. login, sudo, hostname, event ID)..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            onKeyDown={handleSearchSubmit}
          />
        </div>

        {/* Filter tabs */}
        <div style={{ display: 'flex', background: '#0a0e17', border: '2px solid #1e293b', borderRadius: 8, padding: 3, gap: 4, flexWrap: 'wrap' }}>
          {filterTabs.map(t => (
            <button
              key={t.key}
              onClick={() => handleFilterChange(t.key)}
              style={{
                background: filter === t.key ? t.color : 'transparent',
                color: filter === t.key ? (t.key === 'warning' ? '#000' : '#fff') : '#94a3b8',
                border: filter === t.key ? '1.5px solid #000' : 'none',
                borderRadius: 6,
                padding: '5px 12px',
                fontSize: '0.75rem',
                fontWeight: 700,
                cursor: 'pointer',
                fontFamily: 'inherit',
                boxShadow: filter === t.key ? '2px 2px 0px #000' : 'none'
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        <span style={{ color: '#64748b', fontSize: '0.78rem', fontFamily: 'JetBrains Mono, monospace', marginLeft: 'auto' }}>
          Showing {logs.length} of {totalLogs}
        </span>
      </div>

      {apiError && (
        <div style={{
          background: 'rgba(244,63,94,0.1)', border: '2px solid #f43f5e',
          borderRadius: 8, padding: '12px 18px', color: '#f43f5e', fontSize: '0.85rem'
        }}>
          Failed to fetch logs from backend API. Please verify backend service status.
        </div>
      )}

      {/* Logs Table Bento */}
      <div className="bento-card" style={{ padding: 0 }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
            <thead>
              <tr style={{ borderBottom: '2.5px solid #1e293b', background: '#090d16', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem' }}>
                <th style={{ padding: '10px 14px', width: 110 }}>STATUS</th>
                <th style={{ padding: '10px 14px', width: 160 }}>CATEGORY</th>
                <th style={{ padding: '10px 14px' }}>EVENT SUMMARY</th>
                <th style={{ padding: '10px 14px', width: 130 }}>ENDPOINT</th>
                <th style={{ padding: '10px 14px', width: 95 }}>TIME</th>
              </tr>
            </thead>
            <tbody>
              {loading && logs.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ padding: '40px 14px', textAlign: 'center', color: '#64748b' }}>
                    Streaming real-time security events from endpoints...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ padding: '40px 14px', textAlign: 'center', color: '#475569' }}>
                    No events match current filter.
                  </td>
                </tr>
              ) : (
                logs.map((log: any) => (
                  <tr 
                    key={log._id}
                    onClick={() => setSelectedLog(log)}
                    style={{
                      borderBottom: '1px solid #141b2b',
                      cursor: 'pointer',
                      transition: 'background 0.1s'
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = '#0e1627'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <td style={{ padding: '10px 14px' }}>
                      <SeverityBadge severity={log.severity} />
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{
                        display: 'inline-block',
                        padding: '3px 8px',
                        borderRadius: 6,
                        fontSize: '0.73rem',
                        fontWeight: 700,
                        background: '#1e293b',
                        color: '#38bdf8',
                        border: '1px solid #334155'
                      }}>
                        {log.category || 'System Event'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ color: '#f8fafc', fontWeight: 700, fontSize: '0.84rem' }}>
                        {log.friendly_summary || log.message || '—'}
                      </div>
                      {log.friendly_summary && log.friendly_summary !== log.message && (
                        <div style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', marginTop: 3 }}>
                          Technical: {log.message}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '10px 14px', fontWeight: 700, color: '#06b6d4' }}>
                      {log.hostname || '—'}
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', color: '#94a3b8' }}>
                      {log.timestamp ? format(new Date(log.timestamp), 'HH:mm:ss') : '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div style={{
          padding: '12px 18px', borderTop: '2px solid #1e293b',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#090d16'
        }}>
          <span style={{ fontSize: '0.78rem', color: '#64748b' }}>
            Page {page} of {totalPages}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={() => { const p = Math.max(1, page - 1); setPage(p); fetchLogs(p, filter, search); }}
              disabled={page <= 1}
              className="neo-btn neo-btn-ghost"
              style={{ padding: '4px 10px', fontSize: '0.75rem' }}
            >
              Previous
            </button>
            <button
              onClick={() => { const p = Math.min(totalPages, page + 1); setPage(p); fetchLogs(p, filter, search); }}
              disabled={page >= totalPages}
              className="neo-btn neo-btn-ghost"
              style={{ padding: '4px 10px', fontSize: '0.75rem' }}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Log Detail Modal */}
      {selectedLog && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50, padding: 20
        }}>
          <div className="bento-card bento-card-cyan" style={{ width: '100%', maxWidth: 650, padding: 24, background: '#0b0f19' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Terminal size={18} color="#06b6d4" />
                <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc' }}>
                  Endpoint Event Details
                </h3>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="neo-btn neo-btn-ghost"
                style={{ padding: '4px 10px', fontSize: '0.75rem' }}
              >
                Close
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, marginBottom: 14 }}>
              <div>
                <span style={{ fontSize: '0.7rem', color: '#64748b' }}>ENDPOINT:</span>
                <div style={{ fontWeight: 700, color: '#f8fafc' }}>{selectedLog.hostname}</div>
              </div>
              <div>
                <span style={{ fontSize: '0.7rem', color: '#64748b' }}>CATEGORY:</span>
                <div style={{ fontWeight: 700, color: '#38bdf8' }}>{selectedLog.category || 'General'}</div>
              </div>
            </div>

            <div style={{ marginBottom: 14 }}>
              <span style={{ fontSize: '0.7rem', color: '#64748b' }}>EVENT SUMMARY:</span>
              <div style={{
                background: '#070a11', border: '1.5px solid #1e293b',
                borderRadius: 6, padding: '10px 12px', color: '#f8fafc',
                fontSize: '0.88rem', fontWeight: 700, marginTop: 4
              }}>
                {selectedLog.friendly_summary || selectedLog.message}
              </div>
            </div>

            <div style={{ marginBottom: 14 }}>
              <span style={{ fontSize: '0.7rem', color: '#64748b' }}>RAW TECHNICAL LOG:</span>
              <pre style={{
                background: '#05070c', border: '1.5px solid #1e293b',
                borderRadius: 6, padding: '10px 12px', color: '#94a3b8',
                fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace',
                maxHeight: 180, overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: '4px 0 0'
              }}>
                {selectedLog.raw_log || selectedLog.message}
              </pre>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

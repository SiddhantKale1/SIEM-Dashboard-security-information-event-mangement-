import { useState, useEffect } from 'react';
import api from '../services/api';
import { Search, FileText, AlertTriangle, Info, ShieldAlert, Terminal } from 'lucide-react';
import { format } from 'date-fns';

const MOCK_LOGS = [
  { _id: '1', timestamp: new Date().toISOString(), hostname: 'LINUX-SERVER',   source: 'sshd',     event_id: 'sshd',  severity: 'error',       message: 'Failed password for invalid user root from 192.168.1.5 port 52341 ssh2' },
  { _id: '2', timestamp: new Date().toISOString(), hostname: 'WORKSTATION-01', source: 'Security', event_id: 4624,    severity: 'information', message: 'An account was successfully logged on. Subject: SYSTEM' },
  { _id: '3', timestamp: new Date().toISOString(), hostname: 'LINUX-SERVER',   source: 'sudo',     event_id: 'sudo',  severity: 'warning',     message: 'sidd : TTY=pts/0 ; PWD=/home/sidd ; USER=root ; COMMAND=/bin/bash' },
  { _id: '4', timestamp: new Date().toISOString(), hostname: 'WORKSTATION-01', source: 'Security', event_id: 4625,    severity: 'error',       message: 'An account failed to log on. Logon Type: 3' },
];

function SeverityIcon({ severity }: { severity: string }) {
  if (severity === 'error')   return <AlertTriangle size={14} color="#f87171" />;
  if (severity === 'warning') return <ShieldAlert   size={14} color="#fbbf24" />;
  return <Info size={14} color="#60a5fa" />;
}

export default function Logs() {
  const [logs, setLogs]     = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'error' | 'warning' | 'information'>('all');

  useEffect(() => {
    api.get('/logs')
      .then(r => setLogs(r.data))
      .catch(() => setLogs(MOCK_LOGS))
      .finally(() => setLoading(false));
  }, []);

  const filtered = logs.filter(l => {
    const matchSearch =
      l.hostname?.toLowerCase().includes(search.toLowerCase()) ||
      l.message?.toLowerCase().includes(search.toLowerCase()) ||
      String(l.event_id).toLowerCase().includes(search.toLowerCase());
    const matchFilter = filter === 'all' || l.severity === filter;
    return matchSearch && matchFilter;
  });

  const counts = {
    error:       logs.filter(l => l.severity === 'error').length,
    warning:     logs.filter(l => l.severity === 'warning').length,
    information: logs.filter(l => l.severity === 'information').length,
  };

  const filterTabs: { key: typeof filter; label: string; color: string }[] = [
    { key: 'all',         label: `All (${logs.length})`,           color: '#60a5fa' },
    { key: 'error',       label: `Errors (${counts.error})`,       color: '#f87171' },
    { key: 'warning',     label: `Warnings (${counts.warning})`,   color: '#fbbf24' },
    { key: 'information', label: `Info (${counts.information})`,   color: '#94a3b8' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* Header */}
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9', margin: 0, letterSpacing: '-0.02em' }}>
          Log Explorer
        </h1>
        <p style={{ color: '#475569', marginTop: 4, fontSize: '0.875rem' }}>
          Search and filter centralized device events
        </p>
      </div>

      {/* Toolbar */}
      <div className="glass-panel" style={{ padding: '14px 20px', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: 240 }}>
          <Search size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#334155' }} />
          <input
            className="input-field"
            style={{ paddingLeft: 36 }}
            placeholder="Search by keyword, device, event ID…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        {/* Filter tabs */}
        <div style={{ display: 'flex', gap: 6 }}>
          {filterTabs.map(t => (
            <button
              key={t.key}
              onClick={() => setFilter(t.key)}
              style={{
                padding: '6px 13px',
                borderRadius: 8,
                border: `1px solid ${filter === t.key ? `${t.color}40` : 'var(--color-dark-border)'}`,
                background: filter === t.key ? `${t.color}12` : 'transparent',
                color: filter === t.key ? t.color : '#475569',
                fontSize: '0.78rem',
                fontWeight: 500,
                cursor: 'pointer',
                fontFamily: 'inherit',
                transition: 'all 0.15s',
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        <span style={{ color: '#334155', fontSize: '0.8rem', whiteSpace: 'nowrap', marginLeft: 'auto' }}>
          {filtered.length} events
        </span>
      </div>

      {/* Table */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto', maxHeight: 'calc(100vh - 300px)', overflowY: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Device</th>
                <th>Source</th>
                <th>Event ID</th>
                <th>Severity</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', color: '#334155', padding: '48px 0' }}>
                    <Terminal size={20} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.3 }} />
                    Loading events…
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', color: '#334155', padding: '48px 0' }}>
                    <FileText size={20} style={{ display: 'block', margin: '0 auto 10px', opacity: 0.3 }} />
                    No events match your filter
                  </td>
                </tr>
              ) : filtered.map(log => (
                <tr key={log._id}>
                  <td style={{ color: '#475569', fontSize: '0.78rem', whiteSpace: 'nowrap', fontFamily: 'monospace' }}>
                    {format(new Date(log.timestamp), 'MMM d, HH:mm:ss')}
                  </td>
                  <td>
                    <span style={{ color: '#cbd5e1', fontWeight: 500, fontSize: '0.85rem' }}>
                      {log.hostname || '—'}
                    </span>
                  </td>
                  <td style={{ color: '#475569', fontSize: '0.82rem' }}>{log.source || '—'}</td>
                  <td>
                    <span style={{
                      fontFamily: 'monospace', fontSize: '0.78rem',
                      color: '#64748b', background: 'rgba(30,37,53,0.6)',
                      padding: '2px 7px', borderRadius: 5,
                    }}>
                      {log.event_id || '—'}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${log.severity === 'information' ? 'info' : log.severity || 'info'}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                      <SeverityIcon severity={log.severity} />
                      {log.severity || 'info'}
                    </span>
                  </td>
                  <td style={{ color: '#94a3b8', fontSize: '0.82rem', maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {log.message}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

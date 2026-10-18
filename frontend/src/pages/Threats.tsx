import { useState, useEffect } from 'react';
import { 
  CheckCircle2, 
  ExternalLink, 
  Lock, 
  Flame, 
  RefreshCw,
  Search,
  Terminal
} from 'lucide-react';
import { WindowsIcon, LinuxPenguinIcon } from '../components/OSIcons';
import api from '../services/api';
import { useNavigate } from 'react-router-dom';

export default function Threats() {
  const navigate = useNavigate();
  const [anomalies, setAnomalies] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({
    active_threats: 0,
    critical_threats: 0,
    risk_score: 0,
    posture: 'SECURE',
    mitre_distribution: []
  });
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('active');
  const [search, setSearch] = useState('');

  const fetchThreats = async () => {
    setLoading(true);
    try {
      const [listRes, statsRes] = await Promise.all([
        api.get(`/anomalies?status=${filterStatus}&severity=${filterSeverity}`),
        api.get('/anomalies/stats')
      ]);
      setAnomalies(listRes.data.anomalies || []);
      setStats(statsRes.data || {});
    } catch (e) {
      console.error("Failed to load anomalies:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, [filterSeverity, filterStatus]);

  const handleResolve = async (id: string) => {
    try {
      await api.post(`/anomalies/${id}/resolve`);
      fetchThreats();
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Failed to resolve incident");
    }
  };

  const handleIsolate = async (deviceId: string) => {
    try {
      await api.post(`/devices/${deviceId}/isolate`);
      alert("Device isolated successfully!");
      fetchThreats();
    } catch (e: any) {
      alert(e?.response?.data?.detail || "Failed to isolate device");
    }
  };

  const filteredList = anomalies.filter(a => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      a.title?.toLowerCase().includes(q) ||
      a.hostname?.toLowerCase().includes(q) ||
      a.mitre_id?.toLowerCase().includes(q) ||
      a.summary?.toLowerCase().includes(q)
    );
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, margin: 0, letterSpacing: '-0.03em', color: '#f8fafc' }}>
              AI Threat Center & Radar
            </h1>
            <span className="neo-badge neo-badge-critical">
              {stats.active_threats || 0} ACTIVE THREATS
            </span>
          </div>
          <p style={{ margin: '4px 0 0', fontSize: '0.85rem', color: '#64748b' }}>
            Autonomous behavioral anomaly classification, MITRE ATT&CK correlation, and instant remediation
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button 
            onClick={() => fetchThreats()}
            className="neo-btn neo-btn-ghost"
            style={{ padding: '8px 14px', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} /> Refresh Radar
          </button>
          <button 
            onClick={() => navigate('/simulator')}
            className="neo-btn neo-btn-violet"
            style={{ padding: '8px 14px', fontSize: '0.8rem' }}
          >
            <Flame size={14} /> Attack Simulator
          </button>
        </div>
      </div>

      {/* MITRE ATT&CK Tactic Barometer */}
      <div className="bento-card" style={{ padding: '16px 20px', background: '#0a0f1a' }}>
        <div style={{ fontSize: '0.72rem', fontFamily: 'JetBrains Mono, monospace', color: '#8b5cf6', fontWeight: 700, marginBottom: 10 }}>
          ACTIVE MITRE ATT&CK DETECTION VECTORS
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {stats.mitre_distribution?.length === 0 ? (
            <span style={{ fontSize: '0.8rem', color: '#475569' }}>
              No active hostile tactics detected in current sliding window.
            </span>
          ) : (
            stats.mitre_distribution?.map((t: any) => (
              <div 
                key={t.tactic} 
                style={{
                  background: '#070a11', border: '1.5px solid #1e293b',
                  borderRadius: 6, padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 6
                }}
              >
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#f8fafc' }}>{t.tactic}:</span>
                <span style={{ fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, color: '#f43f5e' }}>
                  {t.count} hits
                </span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            background: '#0d131f', border: '2px solid #1e293b',
            borderRadius: 8, padding: '6px 12px', minWidth: 260
          }}>
            <Search size={15} color="#64748b" />
            <input 
              type="text" 
              placeholder="Search by title, host, MITRE..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{
                background: 'transparent', border: 'none', color: '#f8fafc',
                fontSize: '0.82rem', outline: 'none', width: '100%', fontFamily: 'inherit'
              }}
            />
          </div>

          {/* Status Tabs */}
          <div style={{ display: 'flex', background: '#0a0e17', border: '2px solid #1e293b', borderRadius: 8, padding: 2 }}>
            {['active', 'resolved', 'all'].map((st) => (
              <button
                key={st}
                onClick={() => setFilterStatus(st)}
                style={{
                  background: filterStatus === st ? '#1e293b' : 'transparent',
                  color: filterStatus === st ? '#f8fafc' : '#64748b',
                  border: 'none', borderRadius: 6, padding: '5px 12px',
                  fontSize: '0.75rem', fontWeight: 700, textTransform: 'capitalize', cursor: 'pointer'
                }}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Severity Tabs */}
          <div style={{ display: 'flex', background: '#0a0e17', border: '2px solid #1e293b', borderRadius: 8, padding: 2 }}>
            {['all', 'critical', 'high', 'medium'].map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                style={{
                  background: filterSeverity === sev ? (sev === 'critical' ? '#f43f5e' : sev === 'high' ? '#f97316' : '#1e293b') : 'transparent',
                  color: filterSeverity === sev ? '#ffffff' : '#64748b',
                  border: 'none', borderRadius: 6, padding: '5px 12px',
                  fontSize: '0.75rem', fontWeight: 700, textTransform: 'capitalize', cursor: 'pointer'
                }}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Threats Grid */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: '#64748b' }}>
            Scanning AI detection indices...
          </div>
        ) : filteredList.length === 0 ? (
          <div className="bento-card" style={{ padding: 40, textAlign: 'center' }}>
            <CheckCircle2 size={36} color="#10b981" style={{ margin: '0 auto 12px' }} />
            <h3 style={{ margin: '0 0 6px', fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc' }}>
              No Threats Match Filter
            </h3>
            <p style={{ margin: 0, fontSize: '0.85rem', color: '#64748b' }}>
              {filterStatus === 'active' 
                ? 'All endpoints operating within normal statistical and behavioral baselines.' 
                : 'No historical threats in this category.'}
            </p>
          </div>
        ) : (
          filteredList.map((incident) => {
            const isCritical = incident.severity === 'critical';
            const isHigh = incident.severity === 'high';

            return (
              <div 
                key={incident._id}
                className="bento-card"
                style={{
                  padding: 20,
                  borderColor: isCritical ? '#f43f5e' : isHigh ? '#f97316' : '#1e293b',
                  boxShadow: isCritical ? '4px 4px 0px #be123c' : isHigh ? '4px 4px 0px #9a3412' : '4px 4px 0px #020408'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
                      <span className={`neo-badge neo-badge-${incident.severity}`}>
                        {incident.severity}
                      </span>
                      <span className="neo-badge neo-badge-violet">
                        MITRE {incident.mitre_id}: {incident.mitre_technique}
                      </span>
                      <span className="mono-pill">
                        {incident.confidence}% AI CONFIDENCE
                      </span>
                      <span style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'JetBrains Mono, monospace' }}>
                        Detected: {new Date(incident.detected_at).toLocaleTimeString()}
                      </span>
                    </div>

                    {/* Prominent Machine Origin Banner */}
                    <div style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      background: 'rgba(6, 182, 212, 0.08)', border: '1.5px solid rgba(6, 182, 212, 0.25)',
                      borderRadius: 8, padding: '8px 12px', marginBottom: 12, flexWrap: 'wrap', gap: 8
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          {String(incident.os || '').toLowerCase() === 'windows' ? (
                            <WindowsIcon size={16} />
                          ) : (
                            <LinuxPenguinIcon size={16} />
                          )}
                          <span style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace' }}>
                            SOURCE MACHINE:
                          </span>
                          <span style={{ fontWeight: 800, color: '#f8fafc', fontSize: '0.9rem' }}>
                            {incident.hostname || 'Endpoint'}
                          </span>
                        </div>
                        <span style={{
                          background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8',
                          padding: '2px 8px', borderRadius: 4, fontSize: '0.72rem',
                          fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, border: '1px solid rgba(56, 189, 248, 0.3)'
                        }}>
                          IP: {incident.ip_address || '—'}
                        </span>
                        <span style={{
                          background: 'rgba(139, 92, 246, 0.15)', color: '#c084fc',
                          padding: '2px 8px', borderRadius: 4, fontSize: '0.7rem',
                          fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase'
                        }}>
                          {incident.os || 'OS'}
                        </span>
                      </div>

                      {incident.device_id && (
                        <button
                          type="button"
                          onClick={() => navigate(`/devices/${incident.device_id}`)}
                          className="neo-btn neo-btn-ghost"
                          style={{ padding: '4px 10px', fontSize: '0.72rem', height: 26, gap: 4 }}
                        >
                          <Terminal size={12} /> Inspect Machine &rarr;
                        </button>
                      )}
                    </div>

                    <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc', margin: '0 0 6px' }}>
                      {incident.title}
                    </h3>
                    <p style={{ fontSize: '0.85rem', color: '#94a3b8', margin: '0 0 12px', lineHeight: 1.4 }}>
                      {incident.summary}
                    </p>

                    {/* Technical Root Cause Box */}
                    <div style={{
                      background: '#070a11', border: '1.5px solid #1e293b',
                      borderRadius: 8, padding: '10px 14px', marginBottom: 12
                    }}>
                      <div style={{ fontSize: '0.7rem', fontFamily: 'JetBrains Mono, monospace', color: '#06b6d4', fontWeight: 700, marginBottom: 4 }}>
                        ROOT CAUSE ANALYSIS:
                      </div>
                      <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>
                        {incident.root_cause}
                      </div>
                    </div>

                    {/* Evidence Snippets */}
                    {incident.evidence && incident.evidence.length > 0 && (
                      <div style={{ marginBottom: 12 }}>
                        <div style={{ fontSize: '0.7rem', fontFamily: 'JetBrains Mono, monospace', color: '#64748b', fontWeight: 700, marginBottom: 4 }}>
                          SIGNAL EVIDENCE:
                        </div>
                        <ul style={{ margin: 0, paddingLeft: 18, fontSize: '0.78rem', color: '#94a3b8' }}>
                          {incident.evidence.map((ev: string, idx: number) => (
                            <li key={idx} style={{ fontFamily: 'JetBrains Mono, monospace', margin: '2px 0' }}>{ev}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Mitigation Playbook */}
                    <div style={{ fontSize: '0.78rem', color: '#10b981', fontWeight: 600 }}>
                      Recommended Action: {incident.recommended_action}
                    </div>
                  </div>

                  {/* Actions Column */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 150 }}>
                    <div style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'JetBrains Mono, monospace', textAlign: 'right' }}>
                      TARGET HOST: <strong style={{ color: '#f1f5f9' }}>{incident.hostname}</strong>
                    </div>

                    {incident.status === 'active' ? (
                      <>
                        <button
                          onClick={() => handleIsolate(incident.device_id)}
                          className="neo-btn neo-btn-coral"
                          style={{ padding: '8px 12px', fontSize: '0.78rem' }}
                        >
                          <Lock size={14} /> Isolate Endpoint
                        </button>
                        <button
                          onClick={() => handleResolve(incident._id)}
                          className="neo-btn neo-btn-emerald"
                          style={{ padding: '8px 12px', fontSize: '0.78rem' }}
                        >
                          <CheckCircle2 size={14} /> Mark Resolved
                        </button>
                      </>
                    ) : (
                      <div style={{
                        padding: '6px 12px', background: 'rgba(16,185,129,0.1)',
                        border: '1.5px solid #10b981', borderRadius: 6,
                        color: '#10b981', fontSize: '0.75rem', fontWeight: 700, textAlign: 'center'
                      }}>
                        RESOLVED
                      </div>
                    )}

                    {incident.mitre_url && (
                      <a
                        href={incident.mitre_url}
                        target="_blank"
                        rel="noreferrer"
                        className="neo-btn neo-btn-ghost"
                        style={{ padding: '6px 10px', fontSize: '0.72rem', textDecoration: 'none' }}
                      >
                        <ExternalLink size={12} /> MITRE Matrix
                      </a>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

    </div>
  );
}

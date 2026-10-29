import { useState, useEffect } from 'react';
import { 
  CheckCircle2, 
  ExternalLink, 
  Lock, 
  RefreshCw,
  Search,
  Clock
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
    <div className="flex flex-col gap-5 max-w-[1600px] mx-auto pb-8 font-sans">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-extrabold text-[#111827] tracking-tight">
              AI Threat Center & Radar
            </h1>
            <span className="text-xs font-bold px-2.5 py-0.5 rounded-full bg-[#fee2e2] text-[#991b1b]">
              {stats.active_threats || 0} ACTIVE THREATS
            </span>
          </div>
          <p className="text-xs text-[#6b7280] mt-1 font-medium">
            Autonomous behavioral anomaly classification, MITRE ATT&CK correlation, and instant remediation
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button 
            type="button"
            onClick={() => fetchThreats()}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-white border border-[#e5e7eb] rounded-xl text-xs font-semibold text-[#111827] hover:bg-[#f9fafb] transition-all shadow-2xs"
          >
            <RefreshCw className="w-3.5 h-3.5 text-[#6b7280]" />
            <span>Refresh Radar</span>
          </button>
        </div>
      </div>

      {/* MITRE ATT&CK Tactic Barometer */}
      <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
        <div className="text-xs font-bold text-[#82c341] uppercase tracking-wider mb-3">
          Active MITRE ATT&CK Detection Vectors
        </div>
        <div className="flex gap-2.5 flex-wrap">
          {!stats.mitre_distribution || stats.mitre_distribution.length === 0 ? (
            <span className="text-xs text-[#9ca3af]">
              No active hostile tactics detected in current sliding window.
            </span>
          ) : (
            stats.mitre_distribution.map((t: any) => (
              <div 
                key={t.tactic} 
                className="bg-[#f9fafb] border border-[#e5e7eb] rounded-xl px-3 py-1.5 flex items-center gap-2"
              >
                <span className="text-xs font-bold text-[#111827]">{t.tactic}:</span>
                <span className="text-xs font-extrabold text-[#ef4444]">
                  {t.count} hits
                </span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search Box */}
          <div className="relative w-72">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[#9ca3af]" />
            <input 
              type="text" 
              placeholder="Search by title, host, MITRE..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-white border border-[#e5e7eb] rounded-xl pl-10 pr-4 py-2 text-xs font-medium text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#82c341] transition-all shadow-2xs"
            />
          </div>

          {/* Status Tabs */}
          <div className="flex items-center bg-white border border-[#e5e7eb] rounded-xl p-1 shadow-2xs">
            {['active', 'resolved', 'all'].map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setFilterStatus(st)}
                className={`px-3 py-1 rounded-lg text-xs font-semibold capitalize transition-all ${
                  filterStatus === st 
                    ? 'bg-[#111827] text-white' 
                    : 'text-[#6b7280] hover:text-[#111827]'
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Severity Tabs */}
          <div className="flex items-center bg-white border border-[#e5e7eb] rounded-xl p-1 shadow-2xs">
            {['all', 'critical', 'high', 'medium'].map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setFilterSeverity(sev)}
                className={`px-3 py-1 rounded-lg text-xs font-semibold capitalize transition-all ${
                  filterSeverity === sev 
                    ? sev === 'critical' ? 'bg-[#ef4444] text-white' : sev === 'high' ? 'bg-[#fb923c] text-white' : 'bg-[#111827] text-white'
                    : 'text-[#6b7280] hover:text-[#111827]'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Threats Grid */}
      <div className="flex flex-col gap-4">
        {loading ? (
          <div className="text-center py-10 text-xs text-[#9ca3af]">
            Scanning AI detection indices...
          </div>
        ) : filteredList.length === 0 ? (
          <div className="bg-white rounded-[24px] p-10 border border-[#f0f2f5] text-center shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
            <CheckCircle2 className="w-10 h-10 text-[#82c341] mx-auto mb-3" />
            <h3 className="text-base font-extrabold text-[#111827] mb-1">
              No Threats Match Filter
            </h3>
            <p className="text-xs text-[#6b7280]">
              {filterStatus === 'active' 
                ? 'All endpoints are operating within normal statistical and behavioral baselines.' 
                : 'No historical threats match this category.'}
            </p>
          </div>
        ) : (
          filteredList.map((incident) => {
            const isCritical = incident.severity === 'critical';
            const isHigh = incident.severity === 'high';

            return (
              <div 
                key={incident._id}
                className="bg-white rounded-[24px] p-6 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex flex-col justify-between transition-all hover:border-[#e5e7eb]"
              >
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-3 flex-wrap">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                        isCritical ? 'bg-[#fee2e2] text-[#991b1b]' : isHigh ? 'bg-[#ffedd5] text-[#9a3412]' : 'bg-[#fef9c3] text-[#854d0e]'
                      }`}>
                        {incident.severity}
                      </span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#f3f4f6] text-[#374151]">
                        MITRE {incident.mitre_id}: {incident.mitre_technique}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#f3f4f6] text-[#111827]">
                        {incident.confidence}% AI CONFIDENCE
                      </span>
                      <span className="text-[11px] text-[#9ca3af] flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(incident.detected_at).toLocaleTimeString()}
                      </span>
                    </div>

                    {/* Machine Origin Banner */}
                    <div className="bg-[#f0fdf4] border border-[#dcfce7] rounded-xl px-4 py-2.5 mb-3 flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2">
                        {incident.os === 'windows' ? <WindowsIcon /> : <LinuxPenguinIcon />}
                        <span className="text-xs font-bold text-[#111827]">
                          Host: <span className="font-mono text-[#166534]">{incident.hostname}</span>
                        </span>
                        <span className="text-xs text-[#9ca3af]">({incident.ip_address})</span>
                      </div>
                      <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-white border border-[#e5e7eb] text-[#374151]">
                        ID: {incident.device_id}
                      </span>
                    </div>

                    <h2 className="text-base font-extrabold text-[#111827] mb-1">
                      {incident.title}
                    </h2>
                    <p className="text-xs text-[#4b5563] leading-relaxed">
                      {incident.summary}
                    </p>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => navigate(`/devices/${incident.device_id}`)}
                      className="flex items-center gap-1.5 px-3 py-2 bg-white border border-[#e5e7eb] rounded-xl text-xs font-semibold text-[#111827] hover:bg-[#f9fafb] transition-all"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>Inspect Node</span>
                    </button>

                    {incident.status === 'active' && (
                      <>
                        <button
                          type="button"
                          onClick={() => handleIsolate(incident.device_id)}
                          className="flex items-center gap-1.5 px-3 py-2 bg-[#fee2e2] border border-[#fecaca] rounded-xl text-xs font-bold text-[#991b1b] hover:bg-[#fecaca] transition-all"
                        >
                          <Lock className="w-3.5 h-3.5" />
                          <span>Isolate Device</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleResolve(incident._id)}
                          className="flex items-center gap-1.5 px-3.5 py-2 bg-[#111827] rounded-xl text-xs font-bold text-white hover:bg-black transition-all"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5 text-[#82c341]" />
                          <span>Mark Resolved</span>
                        </button>
                      </>
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

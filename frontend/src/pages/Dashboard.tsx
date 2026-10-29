import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Radio, 
  Activity, 
  Monitor, 
  ArrowUpRight, 
  ArrowDownLeft,
  RefreshCw,
  Plus,
  CheckCircle2
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import api from '../services/api';

export default function Dashboard() {
  const navigate = useNavigate();
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d'>('24h');
  const [loading, setLoading] = useState(false);

  // Live real data from backend
  const [logStats, setLogStats] = useState({
    logs_total: 0,
    logs_today: 0,
    errors: 0,
    warnings: 0
  });

  const [hourlyLogs, setHourlyLogs] = useState<any[]>([]);
  const [aiStats, setAiStats] = useState<any>({
    risk_score: 0,
    posture: 'SECURE',
    active_threats: 0,
    critical_threats: 0,
    total_anomalies: 0,
    mitre_distribution: []
  });

  const [networkInfo, setNetworkInfo] = useState<any>({
    network: { subnet: '192.168.29.0/24', gateway: '192.168.29.1' },
    active_devices_count: 0,
    aggregate_tx_bytes: 0,
    aggregate_rx_bytes: 0
  });

  const [recentIncidents, setRecentIncidents] = useState<any[]>([]);
  const [activeDevices, setActiveDevices] = useState<any[]>([]);

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [statsRes, hourlyRes, aiRes, netRes, devRes, anomRes] = await Promise.all([
        api.get('/logs/stats').catch(() => ({ data: { logs_today: 0, logs_total: 0, errors: 0, warnings: 0 } })),
        api.get(`/logs/hourly?timeframe=${timeRange}`).catch(() => ({ data: [] })),
        api.get('/anomalies/stats').catch(() => ({ data: { risk_score: 0, posture: 'SECURE', active_threats: 0, mitre_distribution: [] } })),
        api.get('/network/traffic').catch(() => ({ data: {} })),
        api.get('/network/active').catch(() => ({ data: { devices: [] } })),
        api.get('/anomalies?status=active&limit=5').catch(() => ({ data: { anomalies: [] } }))
      ]);

      setLogStats(statsRes.data || { logs_today: 0, logs_total: 0, errors: 0, warnings: 0 });
      setHourlyLogs(hourlyRes.data && hourlyRes.data.length > 0 ? hourlyRes.data : [
        { time: '00:00', count: 0 },
        { time: '04:00', count: 0 },
        { time: '08:00', count: 0 },
        { time: '12:00', count: 0 },
        { time: '16:00', count: 0 },
        { time: '20:00', count: 0 },
        { time: '23:59', count: 0 },
      ]);
      setAiStats(aiRes.data || { risk_score: 0, posture: 'SECURE', active_threats: 0, mitre_distribution: [] });
      setNetworkInfo(netRes.data || {});
      setActiveDevices(devRes.data?.devices || []);
      setRecentIncidents(anomRes.data?.anomalies || []);
    } catch (err) {
      console.error("Dashboard telemetry error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000);
    return () => clearInterval(interval);
  }, [timeRange]);

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  const onlineCount = activeDevices.filter(d => d.status === 'online' || d.current_network_state === 'online').length;
  const isolatedCount = activeDevices.filter(d => d.status === 'isolated').length;
  const offlineCount = Math.max(0, activeDevices.length - onlineCount - isolatedCount);

  // Calculate severity distribution percentages
  const totalLogged = logStats.logs_total || 0;
  const errorCount = logStats.errors || 0;
  const warnCount = logStats.warnings || 0;
  const infoCount = Math.max(0, totalLogged - errorCount - warnCount);

  const errorPct = totalLogged > 0 ? Math.round((errorCount / totalLogged) * 100) : 0;
  const warnPct = totalLogged > 0 ? Math.round((warnCount / totalLogged) * 100) : 0;
  const infoPct = totalLogged > 0 ? 100 - errorPct - warnPct : 100;

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 max-w-[1600px] mx-auto pb-8 font-sans">
      
      {/* ── Left / Center Column (8 cols) ── */}
      <div className="xl:col-span-8 flex flex-col gap-5">
        
        {/* ── 4 Top KPI Cards ── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white rounded-[22px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
            <span className="text-[11px] font-semibold text-[#9ca3af] uppercase tracking-wider block">
              Total Ingested Logs
            </span>
            <div className="text-2xl font-extrabold text-[#111827] mt-1.5 tracking-tight">
              {logStats.logs_total.toLocaleString()}
            </div>
            <span className="text-[11px] text-[#6b7280] mt-1 block">
              Across managed fleet
            </span>
          </div>

          <div className="bg-white rounded-[22px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
            <span className="text-[11px] font-semibold text-[#9ca3af] uppercase tracking-wider block">
              Logs Ingested Today
            </span>
            <div className="text-2xl font-extrabold text-[#111827] mt-1.5 tracking-tight">
              {logStats.logs_today.toLocaleString()}
            </div>
            <span className="text-[11px] text-[#65a30d] font-semibold mt-1 flex items-center gap-1">
              <span>↗</span> Live aggregation
            </span>
          </div>

          <div className="bg-white rounded-[22px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
            <span className="text-[11px] font-semibold text-[#9ca3af] uppercase tracking-wider block">
              Active Threats
            </span>
            <div className={`text-2xl font-extrabold mt-1.5 tracking-tight ${aiStats.active_threats > 0 ? 'text-[#ef4444]' : 'text-[#111827]'}`}>
              {aiStats.active_threats}
            </div>
            <span className="text-[11px] text-[#6b7280] mt-1 block">
              {aiStats.active_threats > 0 ? 'Requires SOC action' : 'Zero active breaches'}
            </span>
          </div>

          <div className="bg-white rounded-[22px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
            <span className="text-[11px] font-semibold text-[#9ca3af] uppercase tracking-wider block">
              Connected Endpoints
            </span>
            <div className="text-2xl font-extrabold text-[#111827] mt-1.5 tracking-tight">
              {activeDevices.length}
            </div>
            <span className="text-[11px] text-[#65a30d] font-semibold mt-1 flex items-center gap-1">
              ● {onlineCount} online
            </span>
          </div>
        </div>

        {/* ── Main Ingestion Telemetry Chart Card ── */}
        <div className="bg-white rounded-[24px] p-6 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
          <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-extrabold text-[#111827] tracking-tight">
                  Telemetry Ingestion Stream
                </h3>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#dcfce7] text-[#166534]">
                  REAL-TIME
                </span>
              </div>
              <p className="text-xs text-[#9ca3af] mt-0.5 font-medium">
                Hourly syslog and telemetry distribution received by API gateway
              </p>
            </div>

            <div className="flex items-center gap-2">
              <select 
                aria-label="Select timeframe"
                className="siem-select text-xs py-1 px-3 border border-[#e5e7eb] rounded-full text-[#4b5563] bg-white cursor-pointer font-medium"
                value={timeRange}
                onChange={(e: any) => setTimeRange(e.target.value)}
              >
                <option value="1h">Live (Last 60 Mins)</option>
                <option value="24h">Past 24 Hours</option>
                <option value="7d">Past 7 Days</option>
              </select>

              <button 
                type="button"
                onClick={fetchDashboardData}
                disabled={loading}
                className="p-1.5 rounded-xl border border-[#e5e7eb] text-[#4b5563] hover:text-[#111827] transition-colors"
                title="Refresh Telemetry"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-[#82c341]' : ''}`} />
              </button>
            </div>
          </div>

          {/* Area Chart */}
          <div className="h-56 pt-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={hourlyLogs} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="telemetryGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#82c341" stopOpacity={0.35}/>
                    <stop offset="95%" stopColor="#82c341" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <XAxis 
                  dataKey="time" 
                  stroke="#9ca3af" 
                  fontSize={11} 
                  tickLine={false} 
                  axisLine={{ stroke: '#f0f2f5' }}
                />
                <YAxis 
                  stroke="#9ca3af" 
                  fontSize={11} 
                  tickLine={false} 
                  axisLine={{ stroke: '#f0f2f5' }}
                  allowDecimals={false}
                />
                <Tooltip 
                  contentStyle={{ 
                    background: '#ffffff', 
                    borderRadius: 12, 
                    border: '1px solid #e5e7eb', 
                    fontSize: 12,
                    boxShadow: '0 4px 12px rgba(0,0,0,0.05)'
                  }}
                  formatter={(val: any) => [`${val} logs`, 'Volume']}
                  labelFormatter={(lbl) => `Time: ${lbl}`}
                />
                <Area 
                  type="monotone" 
                  dataKey="count" 
                  stroke="#82c341" 
                  strokeWidth={2.5} 
                  fill="url(#telemetryGradient)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="flex items-center justify-between pt-3 mt-2 border-t border-[#f4f5f7] text-xs text-[#6b7280]">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#82c341]" />
              <span>Log Volume Stream</span>
            </span>
            <button 
              type="button" 
              onClick={() => navigate('/logs')}
              className="font-semibold text-[#111827] hover:text-[#82c341] flex items-center gap-1 transition-colors"
            >
              <span>Explore Raw Stream</span>
              <span>→</span>
            </button>
          </div>
        </div>

        {/* ── Row 2: 3 Core SIEM Analytics Cards ── */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          
          {/* Card 1: Log Level Distribution */}
          <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex flex-col justify-between">
            <div>
              <h4 className="text-sm font-bold text-[#111827]">
                Log Severity Breakdown
              </h4>
              <p className="text-[11px] text-[#9ca3af] font-medium mt-0.5">
                Classification distribution
              </p>

              <div className="mt-4">
                <span className="text-2xl font-extrabold text-[#111827]">
                  {logStats.logs_total.toLocaleString()}
                </span>
                <span className="text-xs text-[#9ca3af] ml-1">total logs</span>

                {/* Segmented bar */}
                <div className="w-full h-3 bg-[#f3f4f6] rounded-full overflow-hidden flex gap-0.5 mt-2.5">
                  <div className="bg-[#82c341] h-full" style={{ width: `${infoPct}%` }} title={`Info: ${infoPct}%`} />
                  <div className="bg-[#facc15] h-full" style={{ width: `${warnPct}%` }} title={`Warning: ${warnPct}%`} />
                  <div className="bg-[#ef4444] h-full" style={{ width: `${errorPct}%` }} title={`Error: ${errorPct}%`} />
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-2 mt-4 text-xs">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-[#4b5563]">
                  <span className="w-2 h-2 rounded-full bg-[#82c341]" />
                  <span>Information</span>
                </span>
                <span className="font-bold text-[#111827]">{infoCount.toLocaleString()} ({infoPct}%)</span>
              </div>

              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-[#4b5563]">
                  <span className="w-2 h-2 rounded-full bg-[#facc15]" />
                  <span>Warnings</span>
                </span>
                <span className="font-bold text-[#111827]">{warnCount.toLocaleString()} ({warnPct}%)</span>
              </div>

              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-[#4b5563]">
                  <span className="w-2 h-2 rounded-full bg-[#ef4444]" />
                  <span>Errors &amp; Alerts</span>
                </span>
                <span className="font-bold text-[#111827]">{errorCount.toLocaleString()} ({errorPct}%)</span>
              </div>
            </div>
          </div>

          {/* Card 2: Security Posture Index */}
          <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex flex-col justify-between">
            <div>
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="text-sm font-bold text-[#111827]">
                    Security Posture Score
                  </h4>
                  <p className="text-[11px] text-[#9ca3af] font-medium mt-0.5">
                    Fleet health compliance
                  </p>
                </div>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                  aiStats.posture === 'SECURE' ? 'bg-[#dcfce7] text-[#166534]' : 'bg-[#fee2e2] text-[#991b1b]'
                }`}>
                  {aiStats.posture}
                </span>
              </div>

              <div className="mt-3">
                <div className="text-2xl font-extrabold text-[#111827]">
                  {Math.max(0, 100 - (aiStats.risk_score || 0))} / 100
                </div>
                <p className="text-[11px] text-[#65a30d] font-semibold mt-0.5">
                  ● Autonomous validation active
                </p>
              </div>
            </div>

            {/* Clean Semi-circle Radial Gauge SVG */}
            <div className="relative flex flex-col items-center justify-center my-2">
              <svg className="w-40 h-22 overflow-visible" viewBox="0 0 100 55">
                <path
                  d="M 10 50 A 40 40 0 0 1 90 50"
                  fill="none"
                  stroke="#f3f4f6"
                  strokeWidth="8"
                  strokeLinecap="round"
                />
                <path
                  d="M 10 50 A 40 40 0 0 1 82 22"
                  fill="none"
                  stroke="url(#postureGradient)"
                  strokeWidth="8"
                  strokeLinecap="round"
                />
                <defs>
                  <linearGradient id="postureGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#a3e635" />
                    <stop offset="100%" stopColor="#82c341" />
                  </linearGradient>
                </defs>
              </svg>

              <div className="absolute bottom-0 text-center flex flex-col items-center">
                <span className="text-2xl font-black text-[#111827] leading-none">
                  {Math.max(0, 100 - (aiStats.risk_score || 0))}%
                </span>
                <span className="text-[10px] text-[#9ca3af] font-medium mt-0.5">
                  System Health Index
                </span>
              </div>
            </div>

            <p className="text-[10px] text-[#9ca3af] text-center leading-tight">
              Aggregated from real-time agent heartbeats and threat heuristics
            </p>
          </div>

          {/* Card 3: MITRE ATT&CK Detections */}
          <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-sm font-bold text-[#111827]">
                  MITRE ATT&amp;CK Radar
                </h4>
                <p className="text-[11px] text-[#9ca3af] font-medium mt-0.5">
                  Hostile tactics detected
                </p>
              </div>
              <button 
                type="button" 
                onClick={() => navigate('/threats')}
                className="text-[11px] font-bold text-[#111827] hover:text-[#82c341] transition-colors"
              >
                Radar →
              </button>
            </div>

            <div className="flex flex-col gap-2 mt-4 text-xs">
              {!aiStats.mitre_distribution || aiStats.mitre_distribution.length === 0 ? (
                <div className="text-center py-6 text-xs text-[#9ca3af]">
                  <CheckCircle2 className="w-8 h-8 text-[#82c341] mx-auto mb-2" />
                  <p className="font-bold text-[#111827]">No Hostile Vectors</p>
                  <p className="text-[11px] mt-0.5">All monitored hosts operating within baseline</p>
                </div>
              ) : (
                aiStats.mitre_distribution.slice(0, 4).map((m: any) => (
                  <div key={m.tactic} className="flex items-center justify-between bg-[#f9fafb] border border-[#f0f2f5] rounded-xl px-3 py-2">
                    <span className="font-semibold text-[#111827] truncate max-w-[140px]">{m.tactic}</span>
                    <span className="font-extrabold text-[#ef4444] text-xs">{m.count} hits</span>
                  </div>
                ))
              )}
            </div>

            <button
              type="button"
              onClick={() => navigate('/threats')}
              className="w-full mt-3 py-2 text-center text-xs font-semibold text-[#6b7280] hover:text-[#111827] border-t border-[#f4f5f7] transition-colors"
            >
              View Threat Engine →
            </button>
          </div>

        </div>

      </div>

      {/* ── Right Column (4 cols) ── */}
      <div className="xl:col-span-4 flex flex-col gap-5">
        
        {/* ── Fleet Endpoint Status Card (NO CREDIT CARDS!) ── */}
        <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-extrabold text-[#111827]">
                Fleet Endpoint Status
              </h3>
              <p className="text-[11px] text-[#9ca3af] font-medium">Monitored Agent Systems</p>
            </div>
            <button 
              type="button" 
              onClick={() => navigate('/endpoints')}
              className="text-xs font-bold text-[#111827] hover:text-[#82c341] flex items-center gap-1 transition-colors"
            >
              <Plus className="w-3.5 h-3.5 text-[#82c341]" />
              <span>Enroll Device</span>
            </button>
          </div>

          {/* Endpoint Status Counters Grid */}
          <div className="grid grid-cols-3 gap-2.5 mb-4">
            <div className="bg-[#f0fdf4] border border-[#dcfce7] rounded-2xl p-3 text-center">
              <span className="text-[10px] font-bold text-[#166534] uppercase block">ONLINE</span>
              <span className="text-xl font-extrabold text-[#166534] mt-0.5 block">{onlineCount}</span>
            </div>
            <div className="bg-[#f9fafb] border border-[#e5e7eb] rounded-2xl p-3 text-center">
              <span className="text-[10px] font-bold text-[#4b5563] uppercase block">OFFLINE</span>
              <span className="text-xl font-extrabold text-[#4b5563] mt-0.5 block">{offlineCount}</span>
            </div>
            <div className="bg-[#fef2f2] border border-[#fee2e2] rounded-2xl p-3 text-center">
              <span className="text-[10px] font-bold text-[#991b1b] uppercase block">ISOLATED</span>
              <span className="text-xl font-extrabold text-[#991b1b] mt-0.5 block">{isolatedCount}</span>
            </div>
          </div>

          {/* Quick Subnet Info Banner */}
          <div className="bg-[#f9fafb] border border-[#f0f2f5] rounded-xl p-3 text-xs font-mono mb-4 flex items-center justify-between">
            <div>
              <span className="text-[10px] text-[#9ca3af] block">ACTIVE SUBNET</span>
              <span className="font-bold text-[#111827]">{networkInfo.network?.subnet || '192.168.29.0/24'}</span>
            </div>
            <div className="text-right">
              <span className="text-[10px] text-[#9ca3af] block">GATEWAY</span>
              <span className="font-semibold text-[#6b7280]">{networkInfo.network?.gateway || '192.168.29.1'}</span>
            </div>
          </div>

          {/* 4 SIEM Action Buttons */}
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => navigate('/endpoints')}
              className="flex items-center justify-center gap-1.5 py-2 px-3 bg-[#111827] text-white rounded-xl text-xs font-semibold hover:bg-black transition-colors"
            >
              <Monitor className="w-3.5 h-3.5 text-[#82c341]" />
              <span>Fleet Roster</span>
            </button>

            <button
              type="button"
              onClick={() => navigate('/network')}
              className="flex items-center justify-center gap-1.5 py-2 px-3 bg-white border border-[#e5e7eb] text-[#111827] rounded-xl text-xs font-semibold hover:bg-[#f9fafb] transition-colors"
            >
              <Radio className="w-3.5 h-3.5 text-[#3b82f6]" />
              <span>Subnet Sweep</span>
            </button>
          </div>
        </div>

        {/* ── Network Traffic Telemetry Card ── */}
        <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)]">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-extrabold text-[#111827]">
                Network Telemetry
              </h3>
              <p className="text-[11px] text-[#9ca3af] font-medium">Real-time socket I/O</p>
            </div>
            <button 
              type="button" 
              onClick={() => navigate('/network')}
              className="text-[#9ca3af] hover:text-[#111827]"
            >
              <Activity className="w-4 h-4 text-[#82c341]" />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3 mt-1">
            <div className="bg-[#f9fafb] border border-[#f0f2f5] rounded-2xl p-3 flex flex-col">
              <span className="text-[10px] font-semibold text-[#9ca3af] flex items-center gap-1">
                <ArrowDownLeft className="w-3 h-3 text-[#82c341]" />
                INBOUND (RX)
              </span>
              <span className="text-base font-extrabold text-[#111827] mt-1 font-mono">
                {formatBytes(networkInfo.aggregate_rx_bytes || 0)}
              </span>
              <span className="text-[10px] text-[#65a30d] font-medium mt-0.5">
                ● Connected flow
              </span>
            </div>

            <div className="bg-[#f9fafb] border border-[#f0f2f5] rounded-2xl p-3 flex flex-col">
              <span className="text-[10px] font-semibold text-[#9ca3af] flex items-center gap-1">
                <ArrowUpRight className="w-3 h-3 text-[#3b82f6]" />
                OUTBOUND (TX)
              </span>
              <span className="text-base font-extrabold text-[#111827] mt-1 font-mono">
                {formatBytes(networkInfo.aggregate_tx_bytes || 0)}
              </span>
              <span className="text-[10px] text-[#3b82f6] font-medium mt-0.5">
                ● Telemetry channel
              </span>
            </div>
          </div>
        </div>

        {/* ── Live Incident Stream (Replacing fake transactions!) ── */}
        <div className="bg-white rounded-[24px] p-5 border border-[#f0f2f5] shadow-[0_1px_3px_rgba(0,0,0,0.02)] flex-1 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-extrabold text-[#111827]">
                  Recent Security Incidents
                </h3>
                <p className="text-[11px] text-[#9ca3af] font-medium">Active behavioral detections</p>
              </div>
              <button 
                type="button" 
                onClick={() => navigate('/threats')}
                className="text-xs font-bold text-[#111827] hover:text-[#82c341] transition-colors"
              >
                All Threats →
              </button>
            </div>

            {/* List of real security incidents */}
            <div className="flex flex-col gap-2.5">
              {recentIncidents.length === 0 ? (
                <div className="text-center py-8 text-xs text-[#9ca3af]">
                  <CheckCircle2 className="w-7 h-7 text-[#82c341] mx-auto mb-2" />
                  <p className="font-bold text-[#111827]">No Active Threats</p>
                  <p className="text-[11px] mt-0.5">Zero unresolved behavioral anomalies detected</p>
                </div>
              ) : (
                recentIncidents.map((incident: any) => {
                  const isCrit = incident.severity === 'critical';
                  const isHigh = incident.severity === 'high';
                  return (
                    <div 
                      key={incident._id}
                      onClick={() => navigate('/threats')}
                      className="p-3 rounded-2xl border border-[#f0f2f5] hover:border-[#e5e7eb] bg-[#fcfcfd] hover:bg-white cursor-pointer transition-all flex items-start justify-between gap-3"
                    >
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-[9px] font-bold px-2 py-0.2 rounded-full uppercase ${
                            isCrit ? 'bg-[#fee2e2] text-[#991b1b]' : isHigh ? 'bg-[#ffedd5] text-[#9a3412]' : 'bg-[#fef9c3] text-[#854d0e]'
                          }`}>
                            {incident.severity}
                          </span>
                          <span className="text-[10px] font-mono text-[#9ca3af]">
                            {incident.hostname}
                          </span>
                        </div>
                        <h5 className="text-xs font-extrabold text-[#111827] line-clamp-1">
                          {incident.title}
                        </h5>
                        <p className="text-[11px] text-[#6b7280] line-clamp-1 mt-0.5">
                          {incident.summary}
                        </p>
                      </div>

                      <span className="text-[10px] text-[#9ca3af] whitespace-nowrap mt-1">
                        {new Date(incident.detected_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          <button 
            type="button"
            onClick={() => navigate('/logs')}
            className="w-full mt-4 py-2 text-center text-xs font-semibold text-[#6b7280] hover:text-[#111827] border-t border-[#f4f5f7] transition-colors"
          >
            Open Centralized Log Stream →
          </button>
        </div>

      </div>

    </div>
  );
}

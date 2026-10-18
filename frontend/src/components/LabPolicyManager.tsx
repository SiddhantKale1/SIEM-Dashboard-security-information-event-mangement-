import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Video, 
  MessageSquare, 
  Gamepad2, 
  DownloadCloud, 
  Plus, 
  Trash2, 
  Check, 
  Globe, 
  RefreshCw,
  AlertOctagon,
  Sparkles
} from 'lucide-react';
import api from '../services/api';

interface PolicyData {
  categories: Record<string, boolean>;
  custom_domains: string[];
  blocked_domains: string[];
  presets: Record<string, {
    title: string;
    description: string;
    domains: string[];
  }>;
  updated_at?: string;
}

export default function LabPolicyManager() {
  const [policy, setPolicy] = useState<PolicyData | null>(null);
  const [loading, setLoading] = useState(true);
  const [togglingCategory, setTogglingCategory] = useState<string | null>(null);
  const [customInput, setCustomInput] = useState('');
  const [addingDomain, setAddingDomain] = useState(false);
  const [statusMsg, setStatusMsg] = useState<{ text: string; type: 'success' | 'error' } | null>(null);

  const fetchPolicy = async () => {
    try {
      const res = await api.get('/policies');
      setPolicy(res.data);
    } catch (err: any) {
      console.error('Failed to load lab policies:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicy();
  }, []);

  const handleToggleCategory = async (key: string) => {
    setTogglingCategory(key);
    try {
      const res = await api.post(`/policies/toggle/${key}`);
      if (policy) {
        setPolicy({
          ...policy,
          categories: {
            ...policy.categories,
            [key]: res.data.is_enabled
          },
          blocked_domains: res.data.blocked_domains
        });
      }
      setStatusMsg({
        text: `${key === 'youtube' ? 'YouTube & Streaming' : key} policy ${res.data.is_enabled ? 'ACTIVATED' : 'DEACTIVATED'} fleet-wide!`,
        type: 'success'
      });
      setTimeout(() => setStatusMsg(null), 4000);
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to toggle policy');
    } finally {
      setTogglingCategory(null);
    }
  };

  const handleAddCustomDomain = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = customInput.trim().toLowerCase();
    if (!clean) return;

    setAddingDomain(true);
    try {
      const res = await api.post('/policies/domains', { domain: clean });
      if (policy) {
        setPolicy({
          ...policy,
          custom_domains: res.data.custom_domains,
          blocked_domains: res.data.blocked_domains
        });
      }
      setCustomInput('');
      setStatusMsg({ text: `Domain '${clean}' added to fleet blocklist!`, type: 'success' });
      setTimeout(() => setStatusMsg(null), 3500);
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to add custom domain');
    } finally {
      setAddingDomain(false);
    }
  };

  const handleRemoveCustomDomain = async (domain: string) => {
    try {
      const res = await api.delete(`/policies/domains/${encodeURIComponent(domain)}`);
      if (policy) {
        setPolicy({
          ...policy,
          custom_domains: res.data.custom_domains,
          blocked_domains: res.data.blocked_domains
        });
      }
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to remove domain');
    }
  };

  if (loading) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
        <RefreshCw size={24} className="animate-spin" style={{ margin: '0 auto 12px' }} />
        Loading Lab Security Policies...
      </div>
    );
  }

  const categoryConfigs: Record<string, { icon: any; color: string; border: string; bg: string }> = {
    youtube: { icon: Video, color: '#ef4444', border: '#b91c1c', bg: 'rgba(239, 68, 68, 0.08)' },
    social_media: { icon: MessageSquare, color: '#ec4899', border: '#be185d', bg: 'rgba(236, 72, 153, 0.08)' },
    gaming: { icon: Gamepad2, color: '#10b981', border: '#047857', bg: 'rgba(16, 185, 129, 0.08)' },
    torrent: { icon: DownloadCloud, color: '#f59e0b', border: '#b45309', bg: 'rgba(245, 158, 11, 0.08)' }
  };

  const totalBlocked = policy?.blocked_domains.length || 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Policy Status Header Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.8) 100%)',
        border: '1px solid #334155',
        borderRadius: 12,
        padding: '20px 24px',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 16
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{
            width: 48,
            height: 48,
            borderRadius: 12,
            background: totalBlocked > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(56, 189, 248, 0.15)',
            border: `1px solid ${totalBlocked > 0 ? '#ef4444' : '#38bdf8'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: totalBlocked > 0 ? '#f87171' : '#38bdf8'
          }}>
            <ShieldAlert size={26} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 800, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 8 }}>
              Workstation Content Blocking & Lab Policies
              <span style={{
                background: totalBlocked > 0 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(148, 163, 184, 0.2)',
                color: totalBlocked > 0 ? '#f87171' : '#94a3b8',
                padding: '2px 8px',
                borderRadius: 9999,
                fontSize: '0.72rem',
                fontWeight: 700
              }}>
                {totalBlocked} DOMAINS RESTRICTED
              </span>
            </h3>
            <p style={{ margin: '4px 0 0', fontSize: '0.82rem', color: '#94a3b8' }}>
              Enforces DNS sinkholes & local <code>/etc/hosts</code> blocks across all enrolled lab endpoints.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            fontSize: '0.75rem',
            fontFamily: 'JetBrains Mono, monospace',
            color: '#34d399',
            background: 'rgba(16, 185, 129, 0.1)',
            padding: '6px 12px',
            borderRadius: 8,
            border: '1px solid rgba(16, 185, 129, 0.3)'
          }}>
            <Sparkles size={13} />
            SYNC REALTIME (15s)
          </span>
          <button
            onClick={fetchPolicy}
            className="neo-btn neo-btn-cyan"
            style={{ padding: '6px 12px', fontSize: '0.78rem' }}
          >
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      {/* Alert toast notification */}
      {statusMsg && (
        <div style={{
          padding: '12px 16px',
          borderRadius: 8,
          background: statusMsg.type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
          border: `1px solid ${statusMsg.type === 'success' ? '#10b981' : '#ef4444'}`,
          color: statusMsg.type === 'success' ? '#6ee7b7' : '#fca5a5',
          fontSize: '0.85rem',
          fontWeight: 700,
          display: 'flex',
          alignItems: 'center',
          gap: 10
        }}>
          <Check size={16} />
          {statusMsg.text}
        </div>
      )}

      {/* Preset Category Toggles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
        {policy && Object.entries(policy.presets).map(([key, preset]) => {
          const cfg = categoryConfigs[key] || {
            icon: AlertOctagon,
            color: '#38bdf8',
            border: '#0284c7',
            bg: 'rgba(56, 189, 248, 0.08)'
          };
          const Icon = cfg.icon;
          const isEnabled = Boolean(policy.categories[key]);
          const isToggling = togglingCategory === key;

          return (
            <div
              key={key}
              style={{
                background: isEnabled ? cfg.bg : '#0b1120',
                border: `2px solid ${isEnabled ? cfg.border : '#1e293b'}`,
                borderRadius: 12,
                padding: 18,
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                transition: 'all 0.2s ease',
                position: 'relative',
                overflow: 'hidden'
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{
                      width: 36,
                      height: 36,
                      borderRadius: 8,
                      background: isEnabled ? cfg.color : '#1e293b',
                      color: isEnabled ? '#ffffff' : '#64748b',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center'
                    }}>
                      <Icon size={18} />
                    </div>
                    <div>
                      <h4 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 800, color: '#f8fafc' }}>
                        {preset.title}
                      </h4>
                      <span style={{ fontSize: '0.72rem', color: isEnabled ? cfg.color : '#64748b', fontWeight: 700 }}>
                        {isEnabled ? 'BLOCKED & RESTRICTED' : 'UNRESTRICTED'}
                      </span>
                    </div>
                  </div>

                  {/* Toggle Button */}
                  <button
                    onClick={() => handleToggleCategory(key)}
                    disabled={isToggling}
                    style={{
                      background: isEnabled ? cfg.color : '#1e293b',
                      border: 'none',
                      borderRadius: 20,
                      width: 52,
                      height: 28,
                      padding: 3,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: isEnabled ? 'flex-end' : 'flex-start',
                      transition: 'all 0.2s ease'
                    }}
                    title={isEnabled ? 'Click to unblock' : 'Click to block'}
                  >
                    <div style={{
                      width: 22,
                      height: 22,
                      borderRadius: '50%',
                      background: '#ffffff',
                      boxShadow: '0 2px 4px rgba(0,0,0,0.4)'
                    }} />
                  </button>
                </div>

                <p style={{ margin: '0 0 14px', fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.4 }}>
                  {preset.description}
                </p>
              </div>

              {/* Sample Domains */}
              <div style={{
                background: '#070a13',
                border: '1px solid #1e293b',
                borderRadius: 8,
                padding: '8px 10px',
                display: 'flex',
                flexWrap: 'wrap',
                gap: 6
              }}>
                {preset.domains.slice(0, 4).map(d => (
                  <span
                    key={d}
                    style={{
                      fontSize: '0.68rem',
                      fontFamily: 'JetBrains Mono, monospace',
                      background: isEnabled ? 'rgba(239, 68, 68, 0.2)' : '#151d2e',
                      color: isEnabled ? '#fca5a5' : '#64748b',
                      padding: '2px 6px',
                      borderRadius: 4
                    }}
                  >
                    {d}
                  </span>
                ))}
                {preset.domains.length > 4 && (
                  <span style={{ fontSize: '0.68rem', color: '#64748b', alignSelf: 'center' }}>
                    +{preset.domains.length - 4} more
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Custom Domain Blocklist Section */}
      <div style={{
        background: '#0b1120',
        border: '1px solid #1e293b',
        borderRadius: 12,
        padding: 22
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div>
            <h4 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 800, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Globe size={18} style={{ color: '#38bdf8' }} />
              Custom Restricted Domains
            </h4>
            <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: '#94a3b8' }}>
              Add any specific domain or website to block on all lab computers (e.g. <code>quora.com</code>, <code>pinterest.com</code>).
            </p>
          </div>
        </div>

        <form onSubmit={handleAddCustomDomain} style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
          <input
            type="text"
            placeholder="Type website to block (e.g. omegle.com, snapchat.com)..."
            value={customInput}
            onChange={(e) => setCustomInput(e.target.value)}
            style={{
              flex: 1,
              background: '#070a13',
              border: '1px solid #334155',
              borderRadius: 8,
              padding: '10px 14px',
              color: '#f8fafc',
              fontSize: '0.85rem',
              fontFamily: 'JetBrains Mono, monospace'
            }}
          />
          <button
            type="submit"
            disabled={addingDomain || !customInput.trim()}
            className="neo-btn neo-btn-cyan"
            style={{ padding: '10px 18px', fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Plus size={14} />
            Block Domain
          </button>
        </form>

        {/* Custom Domains Tag List */}
        {policy && policy.custom_domains.length > 0 ? (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {policy.custom_domains.map(dom => (
              <div
                key={dom}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  background: 'rgba(239, 68, 68, 0.12)',
                  border: '1px solid rgba(239, 68, 68, 0.4)',
                  padding: '6px 10px',
                  borderRadius: 6,
                  fontSize: '0.78rem',
                  fontFamily: 'JetBrains Mono, monospace',
                  color: '#fca5a5'
                }}
              >
                <span>{dom}</span>
                <button
                  onClick={() => handleRemoveCustomDomain(dom)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#f87171',
                    cursor: 'pointer',
                    padding: 0,
                    display: 'flex',
                    alignItems: 'center'
                  }}
                  title="Remove restriction"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: '14px', textAlign: 'center', color: '#64748b', fontSize: '0.82rem', border: '1px dashed #1e293b', borderRadius: 8 }}>
            No custom domains added yet. Use the input above to restrict any custom domain.
          </div>
        )}
      </div>
    </div>
  );
}

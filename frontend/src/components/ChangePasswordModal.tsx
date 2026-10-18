import { useState } from 'react';
import { Lock, Eye, EyeOff, ShieldCheck } from 'lucide-react';
import api from '../services/api';

interface Props {
  username: string;
  onDone: () => void;
}

export default function ChangePasswordModal({ username, onDone }: Props) {
  const [current, setCurrent]     = useState('');
  const [next, setNext]           = useState('');
  const [confirm, setConfirm]     = useState('');
  const [showCur, setShowCur]     = useState(false);
  const [showNew, setShowNew]     = useState(false);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');

  const strength = (pw: string) => {
    if (!pw) return 0;
    let s = 0;
    if (pw.length >= 8)  s++;
    if (/[A-Z]/.test(pw)) s++;
    if (/[0-9]/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    return s;
  };
  const str = strength(next);
  const strLabel = ['', 'Weak', 'Fair', 'Good', 'Strong'][str];
  const strColor = ['', '#f87171', '#fbbf24', '#60a5fa', '#4ade80'][str];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (next !== confirm) { setError('New passwords do not match.'); return; }
    if (next.length < 8)  { setError('Password must be at least 8 characters.'); return; }
    setLoading(true);
    try {
      await api.post('/auth/change-password', { current_password: current, new_password: next });
      onDone();
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to update password.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 10000,
      background: 'rgba(7,10,16,0.92)',
      backdropFilter: 'blur(12px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 20,
    }}>
      <div style={{
        background: 'rgba(14,18,25,0.98)',
        border: '1px solid rgba(59,130,246,0.25)',
        borderRadius: 20,
        padding: 36,
        width: '100%', maxWidth: 420,
        boxShadow: '0 24px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(59,130,246,0.1)',
      }}>
        {/* Icon & title */}
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{
            width: 52, height: 52, borderRadius: 16,
            background: 'rgba(59,130,246,0.12)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            margin: '0 auto 16px',
            border: '1px solid rgba(59,130,246,0.2)',
          }}>
            <ShieldCheck size={24} color="#60a5fa" />
          </div>
          <h2 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700, color: '#f1f5f9', letterSpacing: '-0.02em' }}>
            Change Your Password
          </h2>
          <p style={{ margin: '8px 0 0', color: '#475569', fontSize: '0.85rem' }}>
            Hi <strong style={{ color: '#94a3b8' }}>{username}</strong> — for security, please set a new password before continuing.
          </p>
        </div>

        <form onSubmit={handleSubmit}>
          {/* Current password */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: '0.72rem', color: '#475569', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
              Current Password
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#334155' }} />
              <input
                type={showCur ? 'text' : 'password'}
                className="input-field"
                style={{ paddingLeft: 34, paddingRight: 36 }}
                value={current}
                onChange={e => setCurrent(e.target.value)}
                placeholder="Current password"
                required
              />
              <button type="button" onClick={() => setShowCur(v => !v)}
                style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#334155', padding: 2 }}>
                {showCur ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          {/* New password */}
          <div style={{ marginBottom: 8 }}>
            <label style={{ display: 'block', fontSize: '0.72rem', color: '#475569', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
              New Password
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#334155' }} />
              <input
                type={showNew ? 'text' : 'password'}
                className="input-field"
                style={{ paddingLeft: 34, paddingRight: 36 }}
                value={next}
                onChange={e => setNext(e.target.value)}
                placeholder="At least 8 characters"
                required
              />
              <button type="button" onClick={() => setShowNew(v => !v)}
                style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#334155', padding: 2 }}>
                {showNew ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          {/* Strength meter */}
          {next && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', gap: 4, marginBottom: 4 }}>
                {[1, 2, 3, 4].map(n => (
                  <div key={n} style={{
                    flex: 1, height: 3, borderRadius: 2,
                    background: n <= str ? strColor : 'rgba(30,37,53,0.8)',
                    transition: 'background 0.2s',
                  }} />
                ))}
              </div>
              <span style={{ fontSize: '0.72rem', color: strColor }}>{strLabel}</span>
            </div>
          )}

          {/* Confirm */}
          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', fontSize: '0.72rem', color: '#475569', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
              Confirm New Password
            </label>
            <input
              type="password"
              className="input-field"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              placeholder="Re-enter new password"
              required
            />
            {confirm && next !== confirm && (
              <p style={{ margin: '5px 0 0', color: '#f87171', fontSize: '0.75rem' }}>Passwords do not match</p>
            )}
          </div>

          {error && (
            <div style={{
              background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)',
              borderRadius: 8, padding: '10px 14px', marginBottom: 16,
              color: '#f87171', fontSize: '0.82rem',
            }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            className="btn-primary"
            disabled={loading || next !== confirm || next.length < 8}
            style={{ width: '100%', justifyContent: 'center', opacity: (loading || next !== confirm || next.length < 8) ? 0.6 : 1 }}
          >
            {loading ? 'Updating…' : 'Update Password'}
          </button>
        </form>
      </div>
    </div>
  );
}

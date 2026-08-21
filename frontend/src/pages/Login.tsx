import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, User, Loader2, Eye, EyeOff } from 'lucide-react';
import api from '../services/api';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw]     = useState(false);
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const fd = new FormData();
      fd.append('username', username);
      fd.append('password', password);
      const res = await api.post('/auth/login', fd);
      localStorage.setItem('access_token', res.data.access_token);
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Invalid credentials. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--color-dark-bg)',
      position: 'relative', overflow: 'hidden',
    }}>
      {/* Glow orbs */}
      <div style={{
        position: 'absolute', top: '-20%', left: '-10%',
        width: '60%', height: '60%', borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />
      <div style={{
        position: 'absolute', bottom: '-20%', right: '-10%',
        width: '55%', height: '55%', borderRadius: '50%',
        background: 'radial-gradient(circle, rgba(139,92,246,0.07) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      {/* Card */}
      <div className="glass-panel" style={{ width: '100%', maxWidth: 400, padding: 36, position: 'relative', zIndex: 1 }}>

        {/* Logo */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 32 }}>
          <div style={{
            width: 56, height: 56,
            background: 'linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%)',
            borderRadius: 16,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            marginBottom: 16,
            boxShadow: '0 0 32px rgba(59,130,246,0.3), 0 0 80px rgba(139,92,246,0.15)',
          }}>
            <Shield size={26} color="white" />
          </div>
          <h1 style={{ margin: 0, fontSize: '1.6rem', fontWeight: 800, color: '#f1f5f9', letterSpacing: '-0.03em' }}>
            SIEM<span style={{ color: '#3b82f6' }}>MVP</span>
          </h1>
          <p style={{ margin: '6px 0 0', color: '#334155', fontSize: '0.82rem' }}>
            Security & Telemetry Platform
          </p>
        </div>

        {/* Error */}
        {error && (
          <div style={{
            background: 'rgba(239,68,68,0.08)',
            border: '1px solid rgba(239,68,68,0.2)',
            borderRadius: 10, padding: '11px 14px',
            color: '#f87171', fontSize: '0.82rem',
            marginBottom: 20,
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Username */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{ fontSize: '0.78rem', fontWeight: 600, color: '#475569', letterSpacing: '0.03em' }}>
              USERNAME
            </label>
            <div style={{ position: 'relative' }}>
              <User size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#334155', pointerEvents: 'none' }} />
              <input
                className="input-field"
                style={{ paddingLeft: 36 }}
                type="text"
                placeholder="admin"
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
                autoComplete="username"
              />
            </div>
          </div>

          {/* Password */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{ fontSize: '0.78rem', fontWeight: 600, color: '#475569', letterSpacing: '0.03em' }}>
              PASSWORD
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#334155', pointerEvents: 'none' }} />
              <input
                className="input-field"
                style={{ paddingLeft: 36, paddingRight: 40 }}
                type={showPw ? 'text' : 'password'}
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                autoComplete="current-password"
              />
              <button
                type="button"
                onClick={() => setShowPw(v => !v)}
                style={{
                  position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', cursor: 'pointer', color: '#334155', padding: 0,
                }}
              >
                {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          {/* Default creds hint */}
          <p style={{ margin: 0, fontSize: '0.75rem', color: '#1e2535', textAlign: 'center' }}>
            Default: <span style={{ color: '#2d3748', fontFamily: 'monospace' }}>admin / admin</span>
          </p>

          <button
            type="submit"
            className="btn-primary"
            disabled={loading}
            style={{ width: '100%', justifyContent: 'center', marginTop: 4, padding: '11px' }}
          >
            {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : 'Sign In →'}
          </button>
        </form>
      </div>

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

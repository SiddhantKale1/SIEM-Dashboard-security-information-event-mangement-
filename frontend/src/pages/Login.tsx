import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, User, Eye, EyeOff, Sparkles, ArrowRight } from 'lucide-react';
import api from '../services/api';

export default function Login() {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin');
  const [showPw, setShowPw]     = useState(false);
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const params = new URLSearchParams();
      params.append('username', username.trim());
      params.append('password', password);

      const res = await api.post('/auth/login', params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });

      if (res.data?.access_token) {
        localStorage.setItem('access_token', res.data.access_token);
        navigate('/');
      } else {
        setError('No access token received from server.');
      }
    } catch (err: any) {
      console.error("Login attempt failed:", err);
      const msg = err.response?.data?.detail || err.message || 'Invalid credentials. Please try again.';
      setError(typeof msg === 'string' ? msg : JSON.stringify(msg));
    } finally {
      setLoading(false);
    }
  };

  const fillAdmin = () => {
    setUsername('admin');
    setPassword('admin');
    setError('');
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: '#070a11',
      position: 'relative',
      padding: 20
    }}>
      {/* Cyber Grid Background Texture */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: `
          linear-gradient(to right, rgba(30, 41, 59, 0.25) 1px, transparent 1px),
          linear-gradient(to bottom, rgba(30, 41, 59, 0.25) 1px, transparent 1px)
        `,
        backgroundSize: '36px 36px',
        pointerEvents: 'none',
        opacity: 0.8
      }} />

      {/* Cyber-Neobrutalism Bento Card */}
      <div 
        className="bento-card bento-card-cyan" 
        style={{
          width: '100%',
          maxWidth: 420,
          padding: 32,
          position: 'relative',
          zIndex: 1,
          background: '#0d131f'
        }}
      >
        {/* Brand Icon & Heading */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 28, textAlign: 'center' }}>
          <div style={{
            width: 52,
            height: 52,
            background: '#8b5cf6',
            borderRadius: 12,
            border: '2.5px solid #000',
            boxShadow: '4px 4px 0px #000',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 14
          }}>
            <Sparkles size={28} color="#ffffff" />
          </div>

          <h1 style={{ margin: 0, fontSize: '1.65rem', fontWeight: 900, color: '#f8fafc', letterSpacing: '-0.03em' }}>
            AETHER<span style={{ color: '#06b6d4' }}>SIEM</span>
          </h1>
          <p style={{ margin: '4px 0 0', color: '#64748b', fontSize: '0.8rem', fontFamily: 'JetBrains Mono, monospace' }}>
            AI-DRIVEN SECURITY MONITORING
          </p>
        </div>

        {/* Error Notification */}
        {error && (
          <div style={{
            background: 'rgba(244,63,94,0.12)',
            border: '2px solid #f43f5e',
            borderRadius: 8,
            padding: '10px 14px',
            color: '#f43f5e',
            fontSize: '0.82rem',
            fontWeight: 700,
            marginBottom: 18,
            boxShadow: '2px 2px 0px #000'
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Username */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{ fontSize: '0.72rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, color: '#94a3b8', letterSpacing: '0.04em' }}>
              OPERATOR USERNAME
            </label>
            <div style={{ position: 'relative' }}>
              <User size={16} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#64748b', pointerEvents: 'none' }} />
              <input
                style={{
                  width: '100%',
                  background: '#070a11',
                  border: '2px solid #1e293b',
                  borderRadius: 8,
                  padding: '10px 12px 10px 38px',
                  color: '#f8fafc',
                  fontSize: '0.88rem',
                  fontWeight: 600,
                  outline: 'none',
                  fontFamily: 'inherit',
                  transition: 'border-color 0.15s'
                }}
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
            <label style={{ fontSize: '0.72rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, color: '#94a3b8', letterSpacing: '0.04em' }}>
              ACCESS CREDENTIAL
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={16} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#64748b', pointerEvents: 'none' }} />
              <input
                style={{
                  width: '100%',
                  background: '#070a11',
                  border: '2px solid #1e293b',
                  borderRadius: 8,
                  padding: '10px 40px 10px 38px',
                  color: '#f8fafc',
                  fontSize: '0.88rem',
                  fontWeight: 600,
                  outline: 'none',
                  fontFamily: 'inherit',
                  transition: 'border-color 0.15s'
                }}
                type={showPw ? 'text' : 'password'}
                placeholder="admin"
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
                  background: 'none', border: 'none', cursor: 'pointer', color: '#64748b', padding: 0,
                }}
              >
                {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {/* 1-Click Credential Preset */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '8px 12px',
            background: '#070a11',
            borderRadius: 6,
            border: '1.5px solid #1e293b'
          }}>
            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
              Default: <strong style={{ color: '#06b6d4', fontFamily: 'JetBrains Mono, monospace' }}>admin / admin</strong>
            </span>
            <button
              type="button"
              onClick={fillAdmin}
              style={{
                background: 'none', border: 'none', color: '#38bdf8',
                fontSize: '0.72rem', fontWeight: 700, cursor: 'pointer', textDecoration: 'underline'
              }}
            >
              Fill Credentials
            </button>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className="neo-btn neo-btn-cyan"
            style={{ width: '100%', padding: '12px', fontSize: '0.9rem', marginTop: 6 }}
          >
            {loading ? 'Authenticating...' : (
              <>
                Enter Defense Matrix <ArrowRight size={16} />
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}

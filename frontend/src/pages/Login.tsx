import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ShieldCheck, 
  Lock, 
  User, 
  Eye, 
  EyeOff, 
  ArrowRight, 
  AlertCircle, 
  KeyRound,
  HelpCircle,
  Activity
} from 'lucide-react';
import api from '../services/api';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [gatewayOnline, setGatewayOnline] = useState<boolean | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const navigate = useNavigate();

  // Load remembered username if present
  useEffect(() => {
    const savedUser = localStorage.getItem('siem_remembered_username');
    if (savedUser) {
      setUsername(savedUser);
      setRememberMe(true);
    }

    // Ping API gateway health
    api.get('/health')
      .then(() => setGatewayOnline(true))
      .catch(() => setGatewayOnline(false));
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const cleanUser = username.trim();
    if (!cleanUser) {
      setError('Please enter your Administrator Username.');
      return;
    }
    if (!password) {
      setError('Please enter your Access Password.');
      return;
    }

    setLoading(true);

    try {
      const params = new URLSearchParams();
      params.append('username', cleanUser);
      params.append('password', password);

      const res = await api.post('/auth/login', params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });

      if (res.data?.access_token) {
        localStorage.setItem('access_token', res.data.access_token);
        
        if (rememberMe) {
          localStorage.setItem('siem_remembered_username', cleanUser);
        } else {
          localStorage.removeItem('siem_remembered_username');
        }

        // Redirect to dashboard
        navigate('/');
      } else {
        setError('Authentication gateway did not return an access token.');
      }
    } catch (err: any) {
      console.error('Login attempt failed:', err);
      if (err.response?.status === 401) {
        setError('Invalid operator credentials. Access denied.');
      } else if (err.code === 'ERR_NETWORK' || !err.response) {
        setError('Cannot reach SIEM Gateway server. Ensure the backend is active on port 8000.');
      } else {
        const detail = err.response?.data?.detail;
        setError(typeof detail === 'string' ? detail : 'Authentication request failed.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'radial-gradient(ellipse at top, #0d1527 0%, #050811 100%)',
      position: 'relative',
      padding: '24px',
      overflow: 'hidden'
    }}>
      {/* Background Cyber Grid */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: `
          linear-gradient(to right, rgba(30, 41, 59, 0.22) 1px, transparent 1px),
          linear-gradient(to bottom, rgba(30, 41, 59, 0.22) 1px, transparent 1px)
        `,
        backgroundSize: '40px 40px',
        pointerEvents: 'none'
      }} />

      {/* Ambient Lighting Orbs */}
      <div style={{
        position: 'absolute',
        top: '15%',
        left: '20%',
        width: 380,
        height: 380,
        background: 'rgba(6, 182, 212, 0.06)',
        filter: 'blur(120px)',
        borderRadius: '50%',
        pointerEvents: 'none'
      }} />
      <div style={{
        position: 'absolute',
        bottom: '15%',
        right: '20%',
        width: 420,
        height: 420,
        background: 'rgba(139, 92, 246, 0.05)',
        filter: 'blur(140px)',
        borderRadius: '50%',
        pointerEvents: 'none'
      }} />

      {/* Main Login Card */}
      <div style={{
        width: '100%',
        maxWidth: 460,
        background: 'rgba(13, 20, 36, 0.85)',
        backdropFilter: 'blur(16px)',
        border: '1px solid rgba(56, 189, 248, 0.2)',
        borderRadius: 20,
        padding: '36px 32px',
        position: 'relative',
        zIndex: 2,
        boxShadow: '0 25px 60px -15px rgba(0, 0, 0, 0.7), 0 0 30px 0 rgba(6, 182, 212, 0.1)'
      }}>

        {/* Top Header & Branding */}
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <div style={{
            width: 58,
            height: 58,
            margin: '0 auto 16px',
            background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.2) 0%, rgba(59, 130, 246, 0.2) 100%)',
            border: '1.5px solid #06b6d4',
            borderRadius: 16,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#38bdf8',
            boxShadow: '0 0 20px rgba(6, 182, 212, 0.3)'
          }}>
            <ShieldCheck size={32} />
          </div>

          <h1 style={{
            margin: 0,
            fontSize: '1.65rem',
            fontWeight: 900,
            color: '#f8fafc',
            letterSpacing: '-0.02em',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 8
          }}>
            AETHER <span style={{ color: '#06b6d4' }}>SIEM</span>
          </h1>

          <p style={{
            margin: '6px 0 0',
            fontSize: '0.8rem',
            color: '#94a3b8',
            fontFamily: 'JetBrains Mono, monospace',
            letterSpacing: '0.05em',
            textTransform: 'uppercase'
          }}>
            Enterprise Security Operations Center
          </p>

          {/* Gateway Status Badge */}
          <div style={{ marginTop: 12, display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 10px', borderRadius: 9999, background: '#070c18', border: '1px solid #1e293b', fontSize: '0.72rem', fontFamily: 'JetBrains Mono, monospace' }}>
            <span style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: gatewayOnline === true ? '#10b981' : gatewayOnline === false ? '#ef4444' : '#f59e0b',
              boxShadow: gatewayOnline === true ? '0 0 8px #10b981' : 'none'
            }} />
            <span style={{ color: gatewayOnline === true ? '#6ee7b7' : gatewayOnline === false ? '#fca5a5' : '#cbd5e1' }}>
              {gatewayOnline === true ? 'AUTHENTICATION GATEWAY: ACTIVE' : gatewayOnline === false ? 'GATEWAY OFFLINE (PORT 8000)' : 'CHECKING GATEWAY...'}
            </span>
          </div>
        </div>

        {/* Error Alert Box */}
        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            borderRadius: 10,
            padding: '12px 14px',
            marginBottom: 20,
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            color: '#fca5a5',
            fontSize: '0.82rem',
            fontWeight: 600,
            lineHeight: 1.4
          }}>
            <AlertCircle size={18} style={{ color: '#ef4444', flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {/* Authentication Form */}
        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          
          {/* Username Field */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{
              fontSize: '0.75rem',
              fontWeight: 800,
              fontFamily: 'JetBrains Mono, monospace',
              color: '#94a3b8',
              letterSpacing: '0.04em'
            }}>
              OPERATOR ID / USERNAME
            </label>
            <div style={{ position: 'relative' }}>
              <User 
                size={17} 
                style={{
                  position: 'absolute',
                  left: 14,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: '#64748b',
                  pointerEvents: 'none'
                }} 
              />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter admin username"
                required
                autoFocus
                autoComplete="username"
                style={{
                  width: '100%',
                  background: '#070c18',
                  border: '1px solid #334155',
                  borderRadius: 10,
                  padding: '12px 14px 12px 42px',
                  color: '#f8fafc',
                  fontSize: '0.9rem',
                  outline: 'none',
                  fontFamily: 'inherit',
                  transition: 'border-color 0.2s, box-shadow 0.2s'
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#06b6d4';
                  e.target.style.boxShadow = '0 0 0 3px rgba(6, 182, 212, 0.15)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = '#334155';
                  e.target.style.boxShadow = 'none';
                }}
              />
            </div>
          </div>

          {/* Password Field */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <label style={{
                fontSize: '0.75rem',
                fontWeight: 800,
                fontFamily: 'JetBrains Mono, monospace',
                color: '#94a3b8',
                letterSpacing: '0.04em'
              }}>
                SECRET KEY / PASSWORD
              </label>
              <button
                type="button"
                onClick={() => setShowHelp(!showHelp)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#38bdf8',
                  fontSize: '0.72rem',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4
                }}
              >
                <HelpCircle size={12} />
                Need Help?
              </button>
            </div>

            <div style={{ position: 'relative' }}>
              <Lock 
                size={17} 
                style={{
                  position: 'absolute',
                  left: 14,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: '#64748b',
                  pointerEvents: 'none'
                }} 
              />
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                required
                autoComplete="current-password"
                style={{
                  width: '100%',
                  background: '#070c18',
                  border: '1px solid #334155',
                  borderRadius: 10,
                  padding: '12px 42px 12px 42px',
                  color: '#f8fafc',
                  fontSize: '0.9rem',
                  outline: 'none',
                  fontFamily: 'inherit',
                  transition: 'border-color 0.2s, box-shadow 0.2s'
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#06b6d4';
                  e.target.style.boxShadow = '0 0 0 3px rgba(6, 182, 212, 0.15)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = '#334155';
                  e.target.style.boxShadow = 'none';
                }}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: 14,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  color: '#64748b',
                  cursor: 'pointer',
                  padding: 0,
                  display: 'flex',
                  alignItems: 'center'
                }}
                title={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </div>
          </div>

          {/* Help Drawer */}
          {showHelp && (
            <div style={{
              background: '#080d1a',
              border: '1px solid #1e293b',
              borderRadius: 8,
              padding: '12px 14px',
              fontSize: '0.78rem',
              color: '#94a3b8',
              lineHeight: 1.5
            }}>
              <p style={{ margin: 0, fontWeight: 700, color: '#f8fafc' }}>
                Default SOC Operator Credentials:
              </p>
              <p style={{ margin: '4px 0 8px', color: '#cbd5e1' }}>
                Username: <code style={{ color: '#38bdf8' }}>admin</code> &bull; Password: <code style={{ color: '#38bdf8' }}>admin</code>
              </p>
              <p style={{ margin: 0, fontSize: '0.72rem', color: '#64748b' }}>
                For credential reset, review security server environment or execute the command-line utility.
              </p>
            </div>
          )}

          {/* Remember Me Toggle */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.8rem', color: '#94a3b8' }}>
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                style={{
                  width: 16,
                  height: 16,
                  accentColor: '#06b6d4',
                  cursor: 'pointer'
                }}
              />
              Remember workstation ID
            </label>

            <span style={{ fontSize: '0.75rem', color: '#475569', display: 'flex', alignItems: 'center', gap: 4 }}>
              <KeyRound size={12} />
              TLS 1.3 Active
            </span>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '13px 20px',
              borderRadius: 10,
              background: loading 
                ? '#1e293b' 
                : 'linear-gradient(135deg, #06b6d4 0%, #2563eb 100%)',
              border: 'none',
              color: '#ffffff',
              fontSize: '0.92rem',
              fontWeight: 800,
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 10,
              boxShadow: loading ? 'none' : '0 4px 14px rgba(6, 182, 212, 0.4)',
              transition: 'transform 0.15s, box-shadow 0.15s',
              marginTop: 6
            }}
            onMouseEnter={(e) => {
              if (!loading) e.currentTarget.style.transform = 'translateY(-1px)';
            }}
            onMouseLeave={(e) => {
              if (!loading) e.currentTarget.style.transform = 'translateY(0)';
            }}
          >
            {loading ? (
              <>
                <Activity size={18} className="animate-spin" />
                <span>Authenticating Operator...</span>
              </>
            ) : (
              <>
                <span>Enter SOC Matrix</span>
                <ArrowRight size={17} />
              </>
            )}
          </button>
        </form>

        {/* Security Compliance Footer */}
        <div style={{
          marginTop: 28,
          paddingTop: 18,
          borderTop: '1px solid #1e293b',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 6,
          textAlign: 'center'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, color: '#64748b', fontSize: '0.72rem' }}>
            <span>SOC 2 Type II</span>
            <span>&bull;</span>
            <span>256-bit AES</span>
            <span>&bull;</span>
            <span>Zero-Trust Architecture</span>
          </div>
          <p style={{ margin: 0, fontSize: '0.68rem', color: '#475569' }}>
            Authorized administrative personnel only. Unauthorized access is logged & investigated.
          </p>
        </div>
      </div>
    </div>
  );
}

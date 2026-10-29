import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Lock, 
  User, 
  Eye, 
  EyeOff, 
  ArrowRight, 
  AlertCircle, 
  HelpCircle,
  Activity,
  CheckCircle2
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

  useEffect(() => {
    const savedUser = localStorage.getItem('siem_remembered_username');
    if (savedUser) {
      setUsername(savedUser);
      setRememberMe(true);
    }

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
        navigate('/', { replace: true });
      } else {
        throw new Error('Authentication response did not contain an access token.');
      }
    } catch (err: any) {
      if (err.response?.status === 401) {
        setError('Invalid username or password. Default admin/admin.');
      } else if (err.code === 'ERR_NETWORK') {
        setError('Cannot reach SIEM Gateway server. Ensure backend is active on port 8000.');
      } else {
        setError(err.response?.data?.detail || 'Authentication failed. Please verify credentials.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemoFill = () => {
    setUsername('admin');
    setPassword('admin');
    setError(null);
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-[#f4f5f7] p-4 font-sans text-[#111827]">
      
      {/* Login Card */}
      <div className="w-full max-w-[420px] bg-white rounded-[28px] border border-[#eaecf0] p-8 shadow-[0_8px_30px_rgba(0,0,0,0.04)] relative">
        
        {/* Brand Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center gap-2 mb-2">
            <span className="text-3xl font-black tracking-tight text-[#111827]">
              SENTINEL
            </span>
            <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-[#82c341]/20 text-[#65a30d]">
              SIEM
            </span>
          </div>
          <p className="text-xs text-[#6b7280] font-medium">
            Centralized Telemetry & Log Management
          </p>

          {/* Gateway Status Badge */}
          <div className="mt-3 inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#f4f5f7] border border-[#e5e7eb] text-[11px] font-medium">
            <span className={`w-2 h-2 rounded-full ${gatewayOnline === true ? 'bg-[#82c341]' : gatewayOnline === false ? 'bg-[#ef4444]' : 'bg-[#facc15]'}`} />
            <span className="text-[#4b5563]">
              {gatewayOnline === true ? 'Gateway Active (Port 8000)' : gatewayOnline === false ? 'Gateway Offline' : 'Connecting...'}
            </span>
          </div>
        </div>

        {/* Error Alert Box */}
        {error && (
          <div className="bg-[#fef2f2] border border-[#fecaca] rounded-xl p-3 mb-4 flex items-center gap-2.5 text-xs text-[#991b1b] font-medium">
            <AlertCircle className="w-4 h-4 text-[#ef4444] shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleLogin} className="flex flex-col gap-4">
          
          {/* Username */}
          <div>
            <label className="block text-xs font-bold text-[#374151] mb-1.5">
              Operator Username
            </label>
            <div className="relative">
              <User className="w-4 h-4 text-[#9ca3af] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username (e.g. admin)"
                required
                className="w-full bg-[#f9fafb] border border-[#e5e7eb] rounded-xl pl-10 pr-4 py-2.5 text-xs font-medium text-[#111827] focus:bg-white focus:outline-none focus:border-[#82c341] transition-all"
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-bold text-[#374151]">
                Password
              </label>
              <button
                type="button"
                onClick={() => setShowHelp(!showHelp)}
                className="text-[11px] text-[#6b7280] hover:text-[#111827] flex items-center gap-1"
              >
                <HelpCircle className="w-3 h-3" />
                <span>Demo Info</span>
              </button>
            </div>
            <div className="relative">
              <Lock className="w-4 h-4 text-[#9ca3af] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password (e.g. admin)"
                required
                className="w-full bg-[#f9fafb] border border-[#e5e7eb] rounded-xl pl-10 pr-10 py-2.5 text-xs font-medium text-[#111827] focus:bg-white focus:outline-none focus:border-[#82c341] transition-all"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 text-[#9ca3af] hover:text-[#4b5563]"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Demo Info Box */}
          {showHelp && (
            <div className="bg-[#f0fdf4] border border-[#bbf7d0] rounded-xl p-3 text-[11px] text-[#166534]">
              <div className="flex items-center justify-between">
                <span>Default Admin Login: <b>admin</b> / <b>admin</b></span>
                <button
                  type="button"
                  onClick={handleQuickDemoFill}
                  className="px-2 py-0.5 bg-[#82c341] text-white rounded-md font-bold text-[10px] hover:bg-[#65a30d]"
                >
                  Auto-fill
                </button>
              </div>
            </div>
          )}

          {/* Remember me */}
          <div className="flex items-center justify-between mt-1">
            <label className="flex items-center gap-2 cursor-pointer text-xs text-[#6b7280]">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="rounded border-[#d1d5db] text-[#82c341] focus:ring-[#82c341]"
              />
              <span>Remember me</span>
            </label>
            <span className="text-[11px] text-[#9ca3af] flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-[#82c341]" />
              SOC Verified
            </span>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 py-3 px-4 bg-[#111827] text-white text-xs font-bold rounded-xl hover:bg-black transition-all shadow-sm flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Activity className="w-4 h-4 animate-spin text-[#82c341]" />
                <span>Signing in...</span>
              </>
            ) : (
              <>
                <span>Sign In to Dashboard</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* Footer */}
        <div className="mt-6 pt-4 border-t border-[#f0f2f5] text-center text-[11px] text-[#9ca3af]">
          Sentinel SIEM v1.0 • Enterprise Security & Observability
        </div>

      </div>
    </div>
  );
}

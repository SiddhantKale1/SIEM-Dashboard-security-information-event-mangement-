import { Monitor } from 'lucide-react';

export function WindowsIcon({ size = 18, color = "#38bdf8" }: { size?: number; color?: string }) {
  return (
    <svg 
      width={size} 
      height={size} 
      viewBox="0 0 24 24" 
      fill={color}
      style={{ display: 'inline-block', verticalAlign: 'middle', flexShrink: 0 }}
    >
      <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.901-1.801" />
    </svg>
  );
}

export function LinuxPenguinIcon({ size = 20 }: { size?: number }) {
  return (
    <svg 
      width={size} 
      height={size} 
      viewBox="0 0 32 32" 
      fill="none"
      style={{ display: 'inline-block', verticalAlign: 'middle', flexShrink: 0 }}
    >
      {/* Tux Penguin SVG */}
      <ellipse cx="16" cy="18" rx="9" ry="11" fill="#0f172a" stroke="#fbbf24" strokeWidth="1" />
      <ellipse cx="16" cy="19" rx="6.5" ry="8.5" fill="#f8fafc" />
      <ellipse cx="16" cy="9" rx="6" ry="6" fill="#0f172a" stroke="#fbbf24" strokeWidth="0.8" />
      {/* Eyes */}
      <ellipse cx="14" cy="8" rx="1.3" ry="1.8" fill="#f8fafc" />
      <ellipse cx="18" cy="8" rx="1.3" ry="1.8" fill="#f8fafc" />
      <circle cx="14" cy="8.2" r="0.75" fill="#020617" />
      <circle cx="18" cy="8.2" r="0.75" fill="#020617" />
      {/* Beak */}
      <path d="M13.5 10.5C13.5 10.5 15 13 16 13C17 13 18.5 10.5 18.5 10.5Z" fill="#f59e0b" stroke="#d97706" strokeWidth="0.5" />
      {/* Feet */}
      <ellipse cx="11.5" cy="28.5" rx="3.5" ry="1.5" fill="#f59e0b" stroke="#d97706" strokeWidth="0.5" />
      <ellipse cx="20.5" cy="28.5" rx="3.5" ry="1.5" fill="#f59e0b" stroke="#d97706" strokeWidth="0.5" />
      {/* Wings */}
      <path d="M7 16C5.5 18.5 5.5 22 7.5 24" stroke="#0f172a" strokeWidth="2.8" strokeLinecap="round" />
      <path d="M25 16C26.5 18.5 26.5 22 24.5 24" stroke="#0f172a" strokeWidth="2.8" strokeLinecap="round" />
    </svg>
  );
}

export function DeviceComputerIcon({ os, size = 18 }: { os?: string; size?: number }) {
  const osLower = (os || '').toLowerCase();
  if (osLower.includes('win')) {
    return <WindowsIcon size={size} />;
  }
  if (osLower.includes('linux') || osLower.includes('ubuntu') || osLower.includes('debian')) {
    return <LinuxPenguinIcon size={size} />;
  }
  return <Monitor size={size} color="#94a3b8" />;
}

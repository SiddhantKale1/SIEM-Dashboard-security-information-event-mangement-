import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import api from '../services/api';

interface Device {
  [key: string]: any;
}

interface DeviceContextType {
  devices: Device[];
  loading: boolean;
  lastFetched: number | null;
  fetchDevices: (forceScan?: boolean) => Promise<void>;
  invalidate: () => void;
}

const DeviceContext = createContext<DeviceContextType | null>(null);

const CACHE_TTL_MS = 30_000; // Only re-fetch from API if data is >30s old

export function DeviceProvider({ children }: { children: ReactNode }) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastFetched, setLastFetched] = useState<number | null>(null);

  const fetchDevices = useCallback(async (forceScan = false) => {
    const now = Date.now();
    // Skip fetch if cache is fresh and not a forced scan
    if (!forceScan && lastFetched && now - lastFetched < CACHE_TTL_MS) {
      return;
    }

    setLoading(true);
    try {
      const res = await api.get(`/network/devices${forceScan ? '?scan=true' : ''}`);
      setDevices(res.data);
      setLastFetched(Date.now());
    } catch (err) {
      console.error('Failed to fetch devices:', err);
    } finally {
      setLoading(false);
    }
  }, [lastFetched]);

  // Call this after enrolling a new device to force a fresh fetch next time
  const invalidate = useCallback(() => {
    setLastFetched(null);
  }, []);

  return (
    <DeviceContext.Provider value={{ devices, loading, lastFetched, fetchDevices, invalidate }}>
      {children}
    </DeviceContext.Provider>
  );
}

export function useDevices() {
  const ctx = useContext(DeviceContext);
  if (!ctx) throw new Error('useDevices must be used within a DeviceProvider');
  return ctx;
}

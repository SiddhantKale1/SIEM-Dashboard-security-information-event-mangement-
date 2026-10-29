import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Threats from './pages/Threats';
import NetworkTraffic from './pages/NetworkTraffic';
import Endpoints from './pages/Endpoints';
import DeviceDetails from './pages/DeviceDetails';
import Logs from './pages/Logs';
import MainLayout from './layouts/MainLayout';
import type { ReactNode } from 'react';

function PrivateRoute({ children }: { children: ReactNode }) {
  const token = localStorage.getItem('access_token');
  return token ? <>{children}</> : <Navigate to="/login" replace />;
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        
        <Route path="/" element={<PrivateRoute><MainLayout /></PrivateRoute>}>
          <Route index element={<Dashboard />} />
          <Route path="threats" element={<Threats />} />
          <Route path="network" element={<NetworkTraffic />} />
          <Route path="endpoints" element={<Endpoints />} />
          <Route path="devices" element={<Endpoints />} />
          <Route path="devices/:id" element={<DeviceDetails />} />
          <Route path="logs" element={<Logs />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;

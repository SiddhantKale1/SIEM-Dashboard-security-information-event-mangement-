import axios from 'axios';

// Dynamically use current hostname so accessing via localhost, 127.0.0.1, or LAN IP works seamlessly
const getBaseUrl = () => {
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL as string;
  }
  const host = typeof window !== 'undefined' && window.location.hostname ? window.location.hostname : 'localhost';
  return `http://${host}:8000/api/v1`;
};

const api = axios.create({
  baseURL: getBaseUrl(),
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Only redirect if an authenticated route fails, NOT the login or register requests/pages themselves!
    if (error.response?.status === 401) {
      const isAuthRequest = 
        error.config?.url?.includes('/auth/login') || 
        error.config?.url?.includes('/auth/register');

      if (!isAuthRequest) {
        localStorage.removeItem('access_token');
        if (typeof window !== 'undefined' && window.location.pathname !== '/login' && window.location.pathname !== '/register') {
          window.location.href = '/login';
        }
      }
    }
    return Promise.reject(error);
  }
);

export default api;

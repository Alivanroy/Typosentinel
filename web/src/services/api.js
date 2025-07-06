import axios from 'axios';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8084/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle common errors
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('token');
      window.location.href = '/login';
    } else if (error.response?.status === 403) {
      // Forbidden - insufficient permissions
      console.error('Access denied: Insufficient permissions');
    } else if (error.response?.status >= 500) {
      // Server error
      console.error('Server error:', error.response.data?.message || 'Internal server error');
    }
    
    return Promise.reject(error);
  }
);

// API endpoints
export const authAPI = {
  login: (credentials) => api.post('/auth/login', credentials),
  logout: () => api.post('/auth/logout'),
  verify: () => api.get('/auth/verify'),
  register: (userData) => api.post('/auth/register', userData),
  refreshToken: () => api.post('/auth/refresh'),
};

export const scanAPI = {
  startScan: (config) => api.post('/scan/start', config),
  getScanResults: (params) => api.get('/scan/results', { params }),
  getScanById: (id) => api.get(`/scan/${id}`),
  deleteScan: (id) => api.delete(`/scan/${id}`),
  getScanHistory: (params) => api.get('/scan/history', { params }),
  downloadReport: (id, format) => api.get(`/scan/${id}/report?format=${format}`, {
    responseType: 'blob',
  }),
};

export const threatAPI = {
  getThreats: (params) => api.get('/threats', { params }),
  getThreatById: (id) => api.get(`/threats/${id}`),
  updateThreatStatus: (id, data) => api.patch(`/threats/${id}/status`, data),
  getThreatStats: (timeRange) => api.get(`/threats/stats?timeRange=${timeRange}`),
  exportThreats: (params) => api.get('/threats/export', {
    params,
    responseType: 'blob',
  }),
  getThreatAnalysis: (params) => api.get('/threats/analysis', { params }),
};

export const dashboardAPI = {
  getMetrics: (timeRange) => api.get(`/dashboard/metrics?timeRange=${timeRange}`),
  getRecentActivity: (limit) => api.get(`/dashboard/activity?limit=${limit}`),
  getSystemHealth: () => api.get('/dashboard/health'),
  getThreatTrends: (timeRange) => api.get(`/dashboard/trends?timeRange=${timeRange}`),
};

export const settingsAPI = {
  getSettings: () => api.get('/settings'),
  updateSettings: (settings) => api.put('/settings', settings),
  getUsers: () => api.get('/settings/users'),
  createUser: (userData) => api.post('/settings/users', userData),
  updateUser: (id, userData) => api.put(`/settings/users/${id}`, userData),
  deleteUser: (id) => api.delete(`/settings/users/${id}`),
  getApiKeys: () => api.get('/settings/api-keys'),
  createApiKey: (keyData) => api.post('/settings/api-keys', keyData),
  revokeApiKey: (id) => api.delete(`/settings/api-keys/${id}`),
};

export default api;
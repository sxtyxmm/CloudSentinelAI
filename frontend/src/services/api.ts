import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auth API
export const authAPI = {
  login: (username: string, password: string) =>
    api.post('/auth/login', new URLSearchParams({ username, password }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }),
  register: (data: any) => api.post('/auth/register', data),
  getCurrentUser: () => api.get('/auth/me'),
};

// Alerts API
export const alertsAPI = {
  getAlerts: (params?: any) => api.get('/alerts/', { params }),
  getAlert: (id: number) => api.get(`/alerts/${id}`),
  updateAlert: (id: number, data: any) => api.patch(`/alerts/${id}`, data),
  submitFeedback: (id: number, data: any) => api.post(`/alerts/${id}/feedback`, data),
  sendNotification: (id: number) => api.post(`/alerts/${id}/notify`),
};

// Dashboard API
export const dashboardAPI = {
  getStats: (params?: any) => api.get('/dashboard/stats', { params }),
  getTrends: (days: number) => api.get('/dashboard/trends', { params: { days } }),
  getTopThreats: (params?: any) => api.get('/dashboard/top-threats', { params }),
  getActivityHeatmap: (days: number) => api.get('/dashboard/activity-heatmap', { params: { days } }),
  getGeographicDistribution: (days: number) => api.get('/dashboard/geographic-distribution', { params: { days } }),
};

// Threats API
export const threatsAPI = {
  analyzeLog: (data: any) => api.post('/threats/analyze', data),
  checkIP: (ip: string) => api.post(`/threats/check-ip/${ip}`),
  ingestAWS: (events: any[]) => api.post('/threats/ingest/aws', events),
  ingestAzure: (events: any[]) => api.post('/threats/ingest/azure', events),
  ingestGCP: (events: any[]) => api.post('/threats/ingest/gcp', events),
};

// Models API
export const modelsAPI = {
  getModels: () => api.get('/models/'),
  getModel: (id: number) => api.get(`/models/${id}`),
  trainModel: (name: string) => api.post('/models/train', null, { params: { model_name: name } }),
  activateModel: (id: number) => api.post(`/models/${id}/activate`),
  getPerformance: (days: number) => api.get('/models/performance/metrics', { params: { days } }),
};

export default api;

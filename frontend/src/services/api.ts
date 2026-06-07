const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const api = {
  getEvents: async (params: Record<string, any> = {}) => {
    const q = new URLSearchParams(params).toString();
    const res = await fetch(`${API_BASE}/api/events?${q}`);
    return res.json();
  },
  getAlerts: async (params: Record<string, any> = {}) => {
    const q = new URLSearchParams(params).toString();
    const res = await fetch(`${API_BASE}/api/alerts?${q}`);
    return res.json();
  },
  acknowledgeAlert: async (id: number) => {
    const res = await fetch(`${API_BASE}/api/alerts/${id}/acknowledge`, { method: 'POST' });
    return res.json();
  },
  getProcessTree: async (pid?: number) => {
    const q = pid ? `?pid=${pid}` : '';
    const res = await fetch(`${API_BASE}/api/process-tree${q}`);
    return res.json();
  },
  getNetwork: async () => {
    const res = await fetch(`${API_BASE}/api/network`);
    return res.json();
  },
  getFirewall: async (params: Record<string, any> = {}) => {
    const q = new URLSearchParams(params).toString();
    const res = await fetch(`${API_BASE}/api/firewall?${q}`);
    return res.json();
  },
  getHistory: async (params: Record<string, any> = {}) => {
    const q = new URLSearchParams(params).toString();
    const res = await fetch(`${API_BASE}/api/history?${q}`);
    return res.json();
  },
  search: async (query: string) => {
    const res = await fetch(`${API_BASE}/api/search?q=${encodeURIComponent(query)}`);
    return res.json();
  },
  getProfile: async () => {
    const res = await fetch(`${API_BASE}/api/profile`);
    return res.json();
  },
  getStartupStatus: async () => {
    const res = await fetch(`${API_BASE}/api/startup/status`);
    return res.json();
  },
  getResource: async () => {
    const res = await fetch(`${API_BASE}/api/resource`);
    return res.json();
  },
  getStats: async () => {
    const res = await fetch(`${API_BASE}/api/stats`);
    return res.json();
  }
};

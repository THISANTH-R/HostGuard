import { create } from 'zustand';
import { Alert, SecurityEvent, NetworkConnection, FirewallEvent, ResourceUsage, DashboardStats } from '../types';

interface AppState {
  theme: 'dark' | 'light';
  toggleTheme: () => void;
  
  alerts: Alert[];
  addAlert: (alert: Alert) => void;
  
  events: SecurityEvent[];
  addEvent: (event: SecurityEvent) => void;
  
  networkConnections: NetworkConnection[];
  addNetworkConnection: (conn: NetworkConnection) => void;
  
  firewallEvents: FirewallEvent[];
  addFirewallEvent: (event: FirewallEvent) => void;
  
  resourceHistory: ResourceUsage[];
  addResourceUsage: (usage: ResourceUsage) => void;
  
  stats: DashboardStats;
  updateStats: (stats: Partial<DashboardStats>) => void;
}

export const useStore = create<AppState>((set) => ({
  theme: 'dark',
  toggleTheme: () => set((state) => ({ theme: state.theme === 'dark' ? 'light' : 'dark' })),
  
  alerts: [],
  addAlert: (alert) => set((state) => ({ alerts: [alert, ...state.alerts].slice(0, 100) })),
  
  events: [],
  addEvent: (event) => set((state) => ({ events: [event, ...state.events].slice(0, 200) })),
  
  networkConnections: [],
  addNetworkConnection: (conn) => set((state) => ({ networkConnections: [conn, ...state.networkConnections].slice(0, 100) })),
  
  firewallEvents: [],
  addFirewallEvent: (event) => set((state) => ({ firewallEvents: [event, ...state.firewallEvents].slice(0, 100) })),
  
  resourceHistory: [],
  addResourceUsage: (usage) => set((state) => ({ resourceHistory: [...state.resourceHistory, usage].slice(-60) })),
  
  stats: {
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0 },
    action_counts: { blocked: 0, killed: 0, suspended: 0, ignored: 0 }
  },
  updateStats: (newStats) => set((state) => ({ stats: { ...state.stats, ...newStats } }))
}));

import React, { createContext, useContext, ReactNode } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { useStore } from '../store/useStore';

const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

interface WSContextType {
  connectedChannels: Record<string, boolean>;
}

const WSContext = createContext<WSContextType>({ connectedChannels: {} });

export const WebSocketProvider = ({ children }: { children: ReactNode }) => {
  const addEvent = useStore(s => s.addEvent);
  const addAlert = useStore(s => s.addAlert);
  const addNetworkConnection = useStore(s => s.addNetworkConnection);
  const addFirewallEvent = useStore(s => s.addFirewallEvent);
  const addResourceUsage = useStore(s => s.addResourceUsage);

  const { isConnected: eventsConnected } = useWebSocket(`${WS_BASE}/ws/events`, addEvent);
  const { isConnected: alertsConnected } = useWebSocket(`${WS_BASE}/ws/alerts`, addAlert);
  const { isConnected: networkConnected } = useWebSocket(`${WS_BASE}/ws/network`, addNetworkConnection);
  const { isConnected: firewallConnected } = useWebSocket(`${WS_BASE}/ws/firewall`, addFirewallEvent);
  const { isConnected: resourceConnected } = useWebSocket(`${WS_BASE}/ws/resource`, addResourceUsage);

  const connectedChannels = {
    events: eventsConnected,
    alerts: alertsConnected,
    network: networkConnected,
    firewall: firewallConnected,
    resource: resourceConnected
  };

  return (
    <WSContext.Provider value={{ connectedChannels }}>
      {children}
    </WSContext.Provider>
  );
};

export const useWSContext = () => useContext(WSContext);

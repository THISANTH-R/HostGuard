import React from 'react';
import { SearchBar } from '../components/SearchBar';
import { SeverityCounters } from '../components/SeverityCounters';
import { AlertFeed } from '../components/AlertFeed';
import { LogStream } from '../components/LogStream';
import { MetricsCards } from '../components/MetricsCards';
import { ProcessTree } from '../components/ProcessTree';
import { useStore } from '../store/useStore';

export const Home = () => {
  const events = useStore(s => s.events);
  const firewallEvents = useStore(s => s.firewallEvents);
  const networkConnections = useStore(s => s.networkConnections);

  return (
    <div className="space-y-6 animate-fade-in">
      <SearchBar />
      
      <SeverityCounters />
      
      <MetricsCards />
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="col-span-1 lg:col-span-2">
          <ProcessTree />
        </div>
        <div className="col-span-1">
          <AlertFeed />
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <LogStream title="System Logs" data={events} type="event" />
        <LogStream title="Firewall Logs" data={firewallEvents} type="firewall" />
        <LogStream title="Network Traffic" data={networkConnections} type="network" />
      </div>
    </div>
  );
};

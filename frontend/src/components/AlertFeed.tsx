import React from 'react';
import { useStore } from '../store/useStore';
import { ShieldAlert, CheckCircle } from 'lucide-react';
import { api } from '../services/api';

const severityColors = {
  critical: 'bg-red-500/10 border-red-500/20 text-red-500',
  high: 'bg-orange-500/10 border-orange-500/20 text-orange-500',
  medium: 'bg-yellow-500/10 border-yellow-500/20 text-yellow-500',
  low: 'bg-green-500/10 border-green-500/20 text-green-500'
};

export const AlertFeed = () => {
  const alerts = useStore(s => s.alerts);
  const theme = useStore(s => s.theme);

  const handleAck = async (id: number) => {
    try {
      await api.acknowledgeAlert(id);
      // Optimistically update or refetch
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className={`rounded-2xl border backdrop-blur-md p-4 ${theme === 'dark' ? 'bg-slate-900/50 border-slate-800' : 'bg-white/50 border-slate-200'} h-[400px] flex flex-col`}>
      <h3 className="text-lg font-bold mb-4 flex items-center">
        <ShieldAlert className="w-5 h-5 mr-2 text-indigo-500" />
        Recent Alerts
      </h3>
      <div className="flex-1 overflow-y-auto space-y-3 pr-2 custom-scrollbar">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-500">
            <CheckCircle className="w-12 h-12 mb-2 opacity-50" />
            <p>No active alerts</p>
          </div>
        ) : (
          alerts.map(alert => (
            <div key={alert.id} className={`p-3 rounded-xl border ${severityColors[alert.severity]} animate-fade-in`}>
              <div className="flex justify-between items-start">
                <div>
                  <h4 className="font-semibold text-sm">{alert.title}</h4>
                  <p className="text-xs opacity-80 mt-1">{alert.details}</p>
                </div>
                <div className="flex flex-col items-end">
                  <span className="text-[10px] opacity-70 whitespace-nowrap">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                  <span className="text-[10px] mt-1 px-1.5 py-0.5 rounded bg-black/10">{alert.mitre}</span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

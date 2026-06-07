import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';
import { Check, ShieldAlert } from 'lucide-react';
import { useStore } from '../store/useStore';

export const Alerts = () => {
  const theme = useStore(s => s.theme);
  
  const { data, refetch } = useQuery({
    queryKey: ['alerts_page'],
    queryFn: () => api.getAlerts()
  });

  const handleAck = async (id: number) => {
    await api.acknowledgeAlert(id);
    refetch();
  };

  return (
    <div className="animate-fade-in max-w-4xl mx-auto">
      <div className="flex items-center mb-8">
        <ShieldAlert className="w-8 h-8 mr-3 text-red-500" />
        <h2 className="text-3xl font-bold">Threat Alerts</h2>
      </div>

      <div className="space-y-4">
        {data?.data?.map((alert: any) => (
          <div key={alert.id} className={`p-5 rounded-2xl border flex flex-col md:flex-row gap-4 justify-between items-start ${theme === 'dark' ? 'bg-slate-900/80 border-slate-700' : 'bg-white border-slate-200 shadow-sm'} ${alert.acknowledged ? 'opacity-60' : ''}`}>
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <span className={`px-2 py-1 rounded text-xs uppercase font-bold
                  ${alert.severity === 'critical' ? 'bg-red-500/20 text-red-500 border border-red-500/20' : 
                    alert.severity === 'high' ? 'bg-orange-500/20 text-orange-500 border border-orange-500/20' : 
                    alert.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-500 border border-yellow-500/20' : 
                    'bg-green-500/20 text-green-500 border border-green-500/20'}`}>
                  {alert.severity}
                </span>
                <span className="px-2 py-1 bg-indigo-500/10 text-indigo-500 border border-indigo-500/20 rounded text-xs font-mono">
                  {alert.mitre}
                </span>
                <span className="text-xs text-slate-500">{new Date(alert.timestamp).toLocaleString()}</span>
              </div>
              <h3 className="text-lg font-bold mb-1">{alert.title}</h3>
              <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{alert.details}</p>
            </div>
            
            <div className="flex flex-col items-end min-w-[120px]">
              <div className="text-center mb-3">
                <div className="text-2xl font-black font-mono tracking-tighter text-indigo-500">{alert.score}</div>
                <div className="text-[10px] uppercase font-bold text-slate-500">Threat Score</div>
              </div>
              {!alert.acknowledged && (
                <button 
                  onClick={() => handleAck(alert.id)}
                  className="flex items-center px-3 py-1.5 rounded bg-slate-800 text-white hover:bg-slate-700 transition-colors text-sm"
                >
                  <Check className="w-4 h-4 mr-1" /> Acknowledge
                </button>
              )}
            </div>
          </div>
        ))}
        {(!data || data.data.length === 0) && (
          <div className="text-center py-12 text-slate-500">No alerts found. System is secure.</div>
        )}
      </div>
    </div>
  );
};

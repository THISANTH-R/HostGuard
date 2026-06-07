import React from 'react';
import { useStore } from '../store/useStore';
import { AlertTriangle, AlertCircle, AlertOctagon, Info } from 'lucide-react';

export const SeverityCounters = () => {
  const stats = useStore(s => s.stats.severity_counts);
  const theme = useStore(s => s.theme);

  const cards = [
    { label: 'Critical', count: stats.critical || 0, color: 'text-red-500', bg: 'bg-red-500/10 border-red-500/20', icon: AlertOctagon, glow: stats.critical > 0 },
    { label: 'High', count: stats.high || 0, color: 'text-orange-500', bg: 'bg-orange-500/10 border-orange-500/20', icon: AlertTriangle, glow: false },
    { label: 'Medium', count: stats.medium || 0, color: 'text-yellow-500', bg: 'bg-yellow-500/10 border-yellow-500/20', icon: AlertCircle, glow: false },
    { label: 'Low', count: stats.low || 0, color: 'text-green-500', bg: 'bg-green-500/10 border-green-500/20', icon: Info, glow: false },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {cards.map((card, i) => (
        <div key={i} className={`relative overflow-hidden rounded-2xl border p-4 backdrop-blur-md transition-all duration-300 hover:scale-[1.02] ${theme === 'dark' ? 'bg-slate-900/50' : 'bg-white/50'} ${card.bg}`}>
          {card.glow && <div className="absolute inset-0 bg-red-500/10 animate-pulse pointer-events-none" />}
          <div className="flex justify-between items-start">
            <div className={`p-2 rounded-xl ${theme === 'dark' ? 'bg-slate-800/50' : 'bg-white/80'}`}>
              <card.icon className={`w-6 h-6 ${card.color}`} />
            </div>
            <span className={`text-3xl font-black ${card.color} font-mono tracking-tighter`}>{card.count}</span>
          </div>
          <h3 className={`mt-4 font-bold uppercase tracking-wider text-sm ${theme === 'dark' ? 'text-slate-300' : 'text-slate-600'}`}>{card.label}</h3>
        </div>
      ))}
    </div>
  );
};

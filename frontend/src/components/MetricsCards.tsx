import React from 'react';
import { useStore } from '../store/useStore';
import { LineChart, Line, ResponsiveContainer, YAxis } from 'recharts';
import { Cpu, HardDrive, MemoryStick } from 'lucide-react';

export const MetricsCards = () => {
  const history = useStore(s => s.resourceHistory);
  const theme = useStore(s => s.theme);
  
  const current = history[history.length - 1] || { cpu_percent: 0, memory_percent: 0, disk_read_bytes: 0, disk_write_bytes: 0 };

  const getMetricColor = (val: number) => val > 85 ? '#ef4444' : val > 60 ? '#f97316' : '#22c55e';
  
  const cards = [
    { title: 'CPU Usage', value: `${current.cpu_percent.toFixed(1)}%`, icon: Cpu, dataKey: 'cpu_percent', color: getMetricColor(current.cpu_percent) },
    { title: 'Memory Usage', value: `${current.memory_percent.toFixed(1)}%`, icon: MemoryStick, dataKey: 'memory_percent', color: getMetricColor(current.memory_percent) },
    { title: 'Disk I/O', value: `${((current.disk_read_bytes + current.disk_write_bytes) / 1024 / 1024).toFixed(1)} MB/s`, icon: HardDrive, dataKey: 'disk_write_bytes', color: '#6366f1' }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {cards.map((card, i) => (
        <div key={i} className={`p-4 rounded-2xl border backdrop-blur-md ${theme === 'dark' ? 'bg-slate-900/50 border-slate-800' : 'bg-white/50 border-slate-200'}`}>
          <div className="flex justify-between items-center mb-2">
            <h4 className="text-sm font-semibold flex items-center text-slate-500">
              <card.icon className="w-4 h-4 mr-2" />
              {card.title}
            </h4>
            <span className="text-lg font-bold" style={{ color: card.color }}>{card.value}</span>
          </div>
          <div className="h-16 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history}>
                <YAxis domain={['dataMin', 'dataMax']} hide />
                <Line type="monotone" dataKey={card.dataKey} stroke={card.color} strokeWidth={2} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      ))}
    </div>
  );
};

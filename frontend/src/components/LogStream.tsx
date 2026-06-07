import React, { useRef, useEffect, useState } from 'react';
import { useStore } from '../store/useStore';
import { Pause, Play, Terminal } from 'lucide-react';

interface LogStreamProps {
  title: string;
  data: any[];
  type: 'event' | 'firewall' | 'network';
}

export const LogStream: React.FC<LogStreamProps> = ({ title, data, type }) => {
  const theme = useStore(s => s.theme);
  const [autoScroll, setAutoScroll] = useState(true);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [data, autoScroll]);

  const renderLogLine = (item: any, i: number) => {
    let msg = '';
    let color = 'text-slate-400';
    
    if (type === 'event') {
      msg = `${item.image || 'Unknown'} - ${item.commandline || 'N/A'}`;
      color = item.severity === 'critical' ? 'text-red-400' : item.severity === 'high' ? 'text-orange-400' : 'text-slate-400';
    } else if (type === 'firewall') {
      msg = `${item.action} ${item.protocol} ${item.src_ip}:${item.src_port} -> ${item.dst_ip}:${item.dst_port}`;
      color = item.action === 'BLOCK' ? 'text-red-400' : 'text-green-400';
    } else if (type === 'network') {
      msg = `${item.process} ${item.local_ip}:${item.local_port} -> ${item.remote_ip}:${item.remote_port} (${item.status})`;
      color = 'text-indigo-400';
    }

    return (
      <div key={i} className="text-[11px] font-mono leading-tight mb-1 animate-fade-in hover:bg-slate-800/50 p-0.5 rounded">
        <span className="text-slate-500 mr-2">[{new Date(item.timestamp).toLocaleTimeString()}]</span>
        <span className={color}>{msg}</span>
      </div>
    );
  };

  return (
    <div className={`rounded-2xl border backdrop-blur-md flex flex-col h-[300px] overflow-hidden ${theme === 'dark' ? 'bg-slate-900/80 border-slate-800' : 'bg-slate-900 border-slate-800'}`}>
      <div className="flex items-center justify-between p-3 border-b border-slate-800 bg-black/20">
        <h3 className="text-sm font-bold text-slate-300 flex items-center">
          <Terminal className="w-4 h-4 mr-2 text-indigo-500" />
          {title}
        </h3>
        <button 
          onClick={() => setAutoScroll(!autoScroll)}
          className={`p-1 rounded bg-black/20 hover:bg-black/40 text-slate-400`}
        >
          {autoScroll ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3 text-indigo-400" />}
        </button>
      </div>
      <div 
        ref={containerRef}
        className="flex-1 overflow-y-auto p-3 custom-scrollbar"
        onScroll={(e) => {
          const t = e.currentTarget;
          const isAtBottom = Math.abs(t.scrollHeight - t.scrollTop - t.clientHeight) < 10;
          if (!isAtBottom && autoScroll) setAutoScroll(false);
        }}
      >
        {data.length === 0 ? (
          <div className="text-xs text-slate-600 font-mono">Waiting for data stream...</div>
        ) : (
          data.slice().reverse().map((item, i) => renderLogLine(item, i))
        )}
      </div>
    </div>
  );
};

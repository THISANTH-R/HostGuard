import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';
import { useStore } from '../store/useStore';
import { Monitor, Cpu, Server, Activity, ShieldCheck, Power } from 'lucide-react';

export const Profile = () => {
  const theme = useStore(s => s.theme);
  
  const { data: sysInfo } = useQuery({ queryKey: ['profile'], queryFn: api.getProfile });
  const { data: startupStatus } = useQuery({ queryKey: ['startup'], queryFn: api.getStartupStatus });

  const InfoCard = ({ icon: Icon, title, value }: any) => (
    <div className={`p-4 rounded-xl border flex items-center gap-4 ${theme === 'dark' ? 'bg-slate-900/50 border-slate-800' : 'bg-white border-slate-200'}`}>
      <div className="p-3 rounded-lg bg-indigo-500/10 text-indigo-500">
        <Icon className="w-6 h-6" />
      </div>
      <div>
        <div className="text-xs font-bold uppercase text-slate-500 mb-0.5">{title}</div>
        <div className="text-sm font-semibold">{value || 'Loading...'}</div>
      </div>
    </div>
  );

  return (
    <div className="animate-fade-in max-w-5xl mx-auto space-y-8">
      <div>
        <h2 className="text-2xl font-bold mb-6 flex items-center">
          <Monitor className="w-6 h-6 mr-2 text-indigo-500" />
          System Information
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <InfoCard icon={Server} title="Hostname" value={sysInfo?.hostname} />
          <InfoCard icon={Monitor} title="OS Version" value={sysInfo?.os_version} />
          <InfoCard icon={Cpu} title="CPU" value={sysInfo?.cpu_info} />
          <InfoCard icon={Activity} title="RAM Total" value={sysInfo?.ram_total} />
          <InfoCard icon={Activity} title="Disk Total" value={sysInfo?.disk_total} />
          <InfoCard icon={Activity} title="Uptime" value={sysInfo?.uptime} />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div>
          <h2 className="text-xl font-bold mb-4 flex items-center">
            <Power className="w-5 h-5 mr-2 text-green-500" />
            Startup Configuration
          </h2>
          <div className={`p-4 rounded-xl border space-y-4 ${theme === 'dark' ? 'bg-slate-900/50 border-slate-800' : 'bg-white border-slate-200'}`}>
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <span className="font-medium">Registry Run Key</span>
              <span className={`px-2 py-1 rounded text-xs font-bold ${startupStatus?.registry_run === 'Enabled' ? 'bg-green-500/20 text-green-500' : 'bg-slate-500/20 text-slate-500'}`}>
                {startupStatus?.registry_run || 'Unknown'}
              </span>
            </div>
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <span className="font-medium">Startup Folder</span>
              <span className={`px-2 py-1 rounded text-xs font-bold ${startupStatus?.startup_folder === 'Enabled' ? 'bg-green-500/20 text-green-500' : 'bg-slate-500/20 text-slate-500'}`}>
                {startupStatus?.startup_folder || 'Unknown'}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="font-medium">Scheduled Task</span>
              <span className={`px-2 py-1 rounded text-xs font-bold ${startupStatus?.scheduled_task === 'Enabled' ? 'bg-green-500/20 text-green-500' : 'bg-slate-500/20 text-slate-500'}`}>
                {startupStatus?.scheduled_task || 'Unknown'}
              </span>
            </div>
          </div>
        </div>

        <div>
          <h2 className="text-xl font-bold mb-4 flex items-center">
            <ShieldCheck className="w-5 h-5 mr-2 text-indigo-500" />
            Collector Status
          </h2>
          <div className={`p-4 rounded-xl border space-y-4 ${theme === 'dark' ? 'bg-slate-900/50 border-slate-800' : 'bg-white border-slate-200'}`}>
             {['Windows Security Logs', 'Sysmon', 'Windows Firewall', 'Network Connections', 'Resource Monitor'].map(collector => (
               <div key={collector} className="flex justify-between items-center border-b last:border-0 border-slate-800 pb-2 last:pb-0">
                 <span className="font-medium text-sm">{collector}</span>
                 <span className="flex items-center text-xs text-green-500 font-bold">
                   <div className="w-2 h-2 rounded-full bg-green-500 mr-2 animate-pulse" /> Active
                 </span>
               </div>
             ))}
          </div>
        </div>
      </div>
    </div>
  );
};

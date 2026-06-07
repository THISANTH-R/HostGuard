import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';
import { Download, FileText } from 'lucide-react';
import { useStore } from '../store/useStore';

export const History = () => {
  const theme = useStore(s => s.theme);
  const [filters, setFilters] = useState({ severity: '', source: '', page: 1 });

  const { data, isLoading } = useQuery({
    queryKey: ['history', filters],
    queryFn: () => api.getHistory(filters)
  });

  return (
    <div className="animate-fade-in space-y-6">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold">Event History</h2>
        <div className="flex gap-2">
          <button className="flex items-center px-4 py-2 rounded-lg bg-indigo-500/10 text-indigo-500 hover:bg-indigo-500/20">
            <Download className="w-4 h-4 mr-2" /> CSV
          </button>
          <button className="flex items-center px-4 py-2 rounded-lg bg-red-500/10 text-red-500 hover:bg-red-500/20">
            <FileText className="w-4 h-4 mr-2" /> PDF
          </button>
        </div>
      </div>

      <div className={`p-4 rounded-xl border ${theme === 'dark' ? 'bg-slate-900/50 border-slate-800' : 'bg-white border-slate-200'} flex gap-4 mb-6`}>
        <select 
          className={`px-3 py-2 rounded-lg border outline-none ${theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-300'}`}
          value={filters.severity}
          onChange={e => setFilters({...filters, severity: e.target.value})}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select 
          className={`px-3 py-2 rounded-lg border outline-none ${theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-300'}`}
          value={filters.source}
          onChange={e => setFilters({...filters, source: e.target.value})}
        >
          <option value="">All Sources</option>
          <option value="winlog">Windows Logs</option>
          <option value="sysmon">Sysmon</option>
          <option value="firewall">Firewall</option>
          <option value="network">Network</option>
        </select>
      </div>

      <div className={`rounded-xl border overflow-hidden ${theme === 'dark' ? 'border-slate-800 bg-slate-900/50' : 'border-slate-200 bg-white'}`}>
        <table className="w-full text-left text-sm">
          <thead className={theme === 'dark' ? 'bg-slate-800/50' : 'bg-slate-50'}>
            <tr>
              <th className="p-4 font-semibold">Timestamp</th>
              <th className="p-4 font-semibold">Source</th>
              <th className="p-4 font-semibold">Severity</th>
              <th className="p-4 font-semibold">Details</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={4} className="p-4 text-center">Loading...</td></tr>
            ) : data?.data?.length === 0 ? (
              <tr><td colSpan={4} className="p-4 text-center">No data found</td></tr>
            ) : (
              data?.data?.map((row: any, i: number) => (
                <tr key={i} className={`border-t ${theme === 'dark' ? 'border-slate-800 hover:bg-slate-800/30' : 'border-slate-200 hover:bg-slate-50'}`}>
                  <td className="p-4 whitespace-nowrap">{new Date(row.timestamp).toLocaleString()}</td>
                  <td className="p-4"><span className="px-2 py-1 bg-slate-500/10 rounded">{row.source}</span></td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded text-xs uppercase font-bold
                      ${row.severity === 'critical' ? 'bg-red-500/20 text-red-500' : 
                        row.severity === 'high' ? 'bg-orange-500/20 text-orange-500' : 
                        row.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-500' : 
                        'bg-green-500/20 text-green-500'}`}>
                      {row.severity}
                    </span>
                  </td>
                  <td className="p-4 font-mono text-xs truncate max-w-md">{row.commandline || row.image || row.details || 'N/A'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

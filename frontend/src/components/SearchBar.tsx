import React from 'react';
import { Search, Loader2 } from 'lucide-react';
import { useSearch } from '../hooks/useSearch';
import { useStore } from '../store/useStore';

export const SearchBar = () => {
  const { query, setQuery, results, isLoading } = useSearch();
  const theme = useStore(s => s.theme);

  return (
    <div className="relative w-full max-w-2xl mx-auto mb-8">
      <div className={`relative flex items-center w-full h-12 rounded-2xl focus-within:ring-2 focus-within:ring-indigo-500 bg-opacity-50 overflow-hidden ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-100'}`}>
        <div className="grid place-items-center h-full w-12 text-slate-400">
          <Search className="h-5 w-5" />
        </div>

        <input
          className="peer h-full w-full outline-none text-sm bg-transparent pr-2"
          type="text"
          id="search"
          placeholder="Search certutil, severity:critical, ip:1.2.3.4..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        
        {isLoading && (
          <div className="grid place-items-center h-full w-12 text-indigo-500">
            <Loader2 className="h-5 w-5 animate-spin" />
          </div>
        )}
      </div>

      {query.length > 2 && results && results.length > 0 && (
        <div className={`absolute top-14 w-full rounded-xl shadow-xl z-50 max-h-96 overflow-y-auto ${theme === 'dark' ? 'bg-slate-800 border border-slate-700' : 'bg-white border border-slate-200'}`}>
          {results.map((res: any, i: number) => (
            <div key={i} className={`p-3 border-b last:border-0 ${theme === 'dark' ? 'border-slate-700 hover:bg-slate-700' : 'border-slate-100 hover:bg-slate-50'} cursor-pointer`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase text-indigo-500 bg-indigo-500/10 px-2 py-1 rounded">{res._type}</span>
                <span className="text-xs text-slate-400">{new Date(res.timestamp).toLocaleString()}</span>
              </div>
              <p className="text-sm mt-1 truncate">
                {res.title || res.commandline || res.action || res.remote_ip || JSON.stringify(res)}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

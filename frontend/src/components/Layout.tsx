import React from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useStore } from '../store/useStore';
import { useWSContext } from '../websocket/WebSocketProvider';
import { Shield, Activity, Bell, User, Moon, Sun, Database } from 'lucide-react';

export const Layout = () => {
  const { theme, toggleTheme } = useStore();
  const { connectedChannels } = useWSContext();
  
  const isConnected = Object.values(connectedChannels).some(Boolean);

  return (
    <div className={`min-h-screen font-sans ${theme === 'dark' ? 'bg-slate-950 text-white' : 'bg-slate-50 text-slate-900'} transition-colors duration-300`}>
      {/* Header */}
      <header className={`sticky top-0 z-50 backdrop-blur-xl ${theme === 'dark' ? 'bg-slate-900/80 border-b border-slate-800' : 'bg-white/80 border-b border-slate-200'} h-16 flex items-center justify-between px-6`}>
        <div className="flex items-center space-x-3">
          <Shield className="w-8 h-8 text-indigo-500" />
          <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-500 to-purple-500">HostGuard</h1>
        </div>
        
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-sm">
            <span className="relative flex h-3 w-3">
              {isConnected && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>}
              <span className={`relative inline-flex rounded-full h-3 w-3 ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></span>
            </span>
            <span className="text-slate-500 dark:text-slate-400">{isConnected ? 'Live' : 'Offline'}</span>
          </div>
          
          <button onClick={toggleTheme} className="p-2 rounded-full hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors">
            {theme === 'dark' ? <Sun className="w-5 h-5 text-yellow-400" /> : <Moon className="w-5 h-5 text-slate-600" />}
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="pb-20 max-w-7xl mx-auto p-4 sm:p-6 lg:p-8">
        <Outlet />
      </main>

      {/* Bottom Nav */}
      <nav className={`fixed bottom-0 w-full backdrop-blur-xl border-t ${theme === 'dark' ? 'bg-slate-900/90 border-slate-800' : 'bg-white/90 border-slate-200'} z-50 pb-safe`}>
        <div className="flex justify-around items-center h-16 max-w-lg mx-auto">
          <NavLink to="/" className={({isActive}) => `flex flex-col items-center p-2 rounded-lg transition-colors ${isActive ? 'text-indigo-500' : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-300'}`}>
            <Activity className="w-6 h-6 mb-1" />
            <span className="text-[10px] uppercase font-semibold">Dashboard</span>
          </NavLink>
          <NavLink to="/history" className={({isActive}) => `flex flex-col items-center p-2 rounded-lg transition-colors ${isActive ? 'text-indigo-500' : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-300'}`}>
            <Database className="w-6 h-6 mb-1" />
            <span className="text-[10px] uppercase font-semibold">History</span>
          </NavLink>
          <NavLink to="/alerts" className={({isActive}) => `flex flex-col items-center p-2 rounded-lg transition-colors ${isActive ? 'text-indigo-500' : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-300'}`}>
            <Bell className="w-6 h-6 mb-1" />
            <span className="text-[10px] uppercase font-semibold">Alerts</span>
          </NavLink>
          <NavLink to="/profile" className={({isActive}) => `flex flex-col items-center p-2 rounded-lg transition-colors ${isActive ? 'text-indigo-500' : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-300'}`}>
            <User className="w-6 h-6 mb-1" />
            <span className="text-[10px] uppercase font-semibold">Profile</span>
          </NavLink>
        </div>
      </nav>
    </div>
  );
};

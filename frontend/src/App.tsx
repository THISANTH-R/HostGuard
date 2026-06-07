import React from 'react';
import { Routes, Route } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Home } from './pages/Home';
import { History } from './pages/History';
import { Alerts } from './pages/Alerts';
import { Profile } from './pages/Profile';
import { WebSocketProvider } from './websocket/WebSocketProvider';

function App() {
  return (
    <WebSocketProvider>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Home />} />
          <Route path="history" element={<History />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="profile" element={<Profile />} />
        </Route>
      </Routes>
    </WebSocketProvider>
  );
}

export default App;

import { useState, useEffect, useRef } from 'react';

export function useWebSocket(url: string, onMessage: (data: any) => void) {
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let timeoutId: any;
    
    const connect = () => {
      const ws = new WebSocket(url);
      
      ws.onopen = () => setIsConnected(true);
      
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onMessage(data);
        } catch (e) {
          console.error("Failed to parse WS message", e);
        }
      };
      
      ws.onclose = () => {
        setIsConnected(false);
        timeoutId = setTimeout(connect, 3000); // Reconnect after 3s
      };
      
      wsRef.current = ws;
    };
    
    connect();
    
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      clearTimeout(timeoutId);
    };
  }, [url, onMessage]);

  return { isConnected };
}

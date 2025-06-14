import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { io, Socket } from 'socket.io-client';
import { useAuth } from './AuthContext';

interface ScanEvent {
  id: string;
  type: 'cli' | 'vscode';
  status: 'started' | 'progress' | 'completed' | 'error';
  data: any;
  timestamp: Date;
}

interface SocketContextType {
  socket: Socket | null;
  connected: boolean;
  scanEvents: ScanEvent[];
  sendMessage: (event: string, data: any) => void;
  clearEvents: () => void;
}

const SocketContext = createContext<SocketContextType | undefined>(undefined);

export const useSocket = (): SocketContextType => {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider');
  }
  return context;
};

interface SocketProviderProps {
  children: ReactNode;
}

export const SocketProvider: React.FC<SocketProviderProps> = ({ children }) => {
  const { user } = useAuth();
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const [scanEvents, setScanEvents] = useState<ScanEvent[]>([]);

  useEffect(() => {
    if (user) {
      // Initialize socket connection
      const newSocket = io(process.env.REACT_APP_SOCKET_URL || 'http://localhost:8080', {
        auth: {
          token: localStorage.getItem('auth_token'),
        },
        transports: ['websocket'],
      });

      newSocket.on('connect', () => {
        console.log('Socket connected');
        setConnected(true);
      });

      newSocket.on('disconnect', () => {
        console.log('Socket disconnected');
        setConnected(false);
      });

      // Listen for scan events from CLI/VSCode extension
      newSocket.on('scan:started', (data) => {
        const event: ScanEvent = {
          id: data.scanId,
          type: data.source,
          status: 'started',
          data,
          timestamp: new Date(),
        };
        setScanEvents(prev => [event, ...prev.slice(0, 99)]); // Keep last 100 events
      });

      newSocket.on('scan:progress', (data) => {
        const event: ScanEvent = {
          id: data.scanId,
          type: data.source,
          status: 'progress',
          data,
          timestamp: new Date(),
        };
        setScanEvents(prev => [event, ...prev.slice(0, 99)]);
      });

      newSocket.on('scan:completed', (data) => {
        const event: ScanEvent = {
          id: data.scanId,
          type: data.source,
          status: 'completed',
          data,
          timestamp: new Date(),
        };
        setScanEvents(prev => [event, ...prev.slice(0, 99)]);
      });

      newSocket.on('scan:error', (data) => {
        const event: ScanEvent = {
          id: data.scanId,
          type: data.source,
          status: 'error',
          data,
          timestamp: new Date(),
        };
        setScanEvents(prev => [event, ...prev.slice(0, 99)]);
      });

      // Listen for policy updates
      newSocket.on('policy:updated', (data) => {
        console.log('Policy updated:', data);
        // Handle policy updates
      });

      // Listen for vulnerability alerts
      newSocket.on('vulnerability:alert', (data) => {
        console.log('Vulnerability alert:', data);
        // Handle vulnerability alerts
      });

      setSocket(newSocket);

      return () => {
        newSocket.close();
      };
    } else {
      // Clean up socket when user logs out
      if (socket) {
        socket.close();
        setSocket(null);
        setConnected(false);
        setScanEvents([]);
      }
    }
  }, [user]);

  const sendMessage = (event: string, data: any) => {
    if (socket && connected) {
      socket.emit(event, data);
    }
  };

  const clearEvents = () => {
    setScanEvents([]);
  };

  const value: SocketContextType = {
    socket,
    connected,
    scanEvents,
    sendMessage,
    clearEvents,
  };

  return (
    <SocketContext.Provider value={value}>
      {children}
    </SocketContext.Provider>
  );
};
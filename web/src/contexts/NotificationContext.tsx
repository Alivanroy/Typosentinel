import React, { createContext, useContext, useState, useCallback } from 'react'
import { ToastContainer } from '../components/ui/Toast'

interface Notification {
  id: string
  type: 'success' | 'error' | 'warning' | 'info'
  message: string
  duration?: number
}

interface NotificationContextType {
  success: (message: string, duration?: number) => void
  showError: (message: string, duration?: number) => void
  warning: (message: string, duration?: number) => void
  info: (message: string, duration?: number) => void
}

const NotificationContext = createContext<NotificationContextType | undefined>(undefined)

export function NotificationProvider({ children }: { children: React.ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([])

  const addNotification = useCallback((type: Notification['type'], message: string, duration = 5000) => {
    const id = Math.random().toString(36).substr(2, 9)
    const notification: Notification = { id, type, message, duration }
    
    setNotifications(prev => [...prev, notification])
  }, [])

  const removeNotification = useCallback((id: string) => {
    setNotifications(prev => prev.filter(notification => notification.id !== id))
  }, [])

  const success = useCallback((message: string, duration?: number) => {
    addNotification('success', message, duration)
  }, [addNotification])

  const showError = useCallback((message: string, duration?: number) => {
    addNotification('error', message, duration)
  }, [addNotification])

  const warning = useCallback((message: string, duration?: number) => {
    addNotification('warning', message, duration)
  }, [addNotification])

  const info = useCallback((message: string, duration?: number) => {
    addNotification('info', message, duration)
  }, [addNotification])

  return (
    <NotificationContext.Provider value={{ success, showError, warning, info }}>
      {children}
      <ToastContainer notifications={notifications} onClose={removeNotification} />
    </NotificationContext.Provider>
  )
}

export function useNotifications() {
  const context = useContext(NotificationContext)
  if (context === undefined) {
    throw new Error('useNotifications must be used within a NotificationProvider')
  }
  return context
}
import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate, useLocation } from 'react-router-dom';
import { logoutUser } from '../../store/slices/authSlice';
import { getSystemHealth } from '../../store/slices/dashboardSlice';
import './Layout.css';

const Layout = ({ children }) => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useSelector(state => state.auth);
  const { systemHealth } = useSelector(state => state.dashboard);

  useEffect(() => {
    // Fetch system health on component mount
    dispatch(getSystemHealth());
    
    // Set up interval to refresh system health
    const interval = setInterval(() => {
      dispatch(getSystemHealth());
    }, 30000); // Every 30 seconds

    return () => clearInterval(interval);
  }, [dispatch]);

  const handleLogout = () => {
    dispatch(logoutUser());
    navigate('/login');
  };

  const navigationItems = [
    {
      path: '/dashboard',
      label: 'Dashboard',
      icon: '📊',
    },
    {
      path: '/scan-results',
      label: 'Scan Results',
      icon: '🔍',
    },
    {
      path: '/threat-analysis',
      label: 'Threat Analysis',
      icon: '⚠️',
    },
    {
      path: '/reports',
      label: 'Reports',
      icon: '📈',
    },
    {
      path: '/documentation',
      label: 'Documentation',
      icon: '📚',
    },
    {
      path: '/settings',
      label: 'Settings',
      icon: '⚙️',
    },
  ];

  const getHealthStatusColor = (status) => {
    switch (status) {
      case 'healthy':
        return '#10b981';
      case 'warning':
        return '#f59e0b';
      case 'critical':
        return '#ef4444';
      default:
        return '#6b7280';
    }
  };

  return (
    <div className="layout">
      {/* Sidebar */}
      <aside className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
        <div className="sidebar-header">
          <div className="logo">
            <span className="logo-icon">🛡️</span>
            {!sidebarCollapsed && <span className="logo-text">TypoSentinel</span>}
          </div>
          <button
            className="sidebar-toggle"
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          >
            {sidebarCollapsed ? '→' : '←'}
          </button>
        </div>

        <nav className="sidebar-nav">
          {navigationItems.map((item) => (
            <button
              key={item.path}
              className={`nav-item ${location.pathname === item.path ? 'active' : ''}`}
              onClick={() => navigate(item.path)}
              title={sidebarCollapsed ? item.label : ''}
            >
              <span className="nav-icon">{item.icon}</span>
              {!sidebarCollapsed && <span className="nav-label">{item.label}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          {!sidebarCollapsed && (
            <div className="system-health">
              <div className="health-indicator">
                <div
                  className="health-dot"
                  style={{ backgroundColor: getHealthStatusColor(systemHealth.status) }}
                />
                <span className="health-text">
                  System {systemHealth.status || 'Unknown'}
                </span>
              </div>
            </div>
          )}
        </div>
      </aside>

      {/* Mobile menu overlay */}
      {mobileMenuOpen && (
        <div className="mobile-menu-overlay" onClick={() => setMobileMenuOpen(false)}>
          <div className="mobile-menu">
            <div className="mobile-menu-header">
              <span className="logo-text">TypoSentinel</span>
              <button onClick={() => setMobileMenuOpen(false)}>✕</button>
            </div>
            <nav className="mobile-nav">
              {navigationItems.map((item) => (
                <button
                  key={item.path}
                  className={`mobile-nav-item ${location.pathname === item.path ? 'active' : ''}`}
                  onClick={() => {
                    navigate(item.path);
                    setMobileMenuOpen(false);
                  }}
                >
                  <span className="nav-icon">{item.icon}</span>
                  <span className="nav-label">{item.label}</span>
                </button>
              ))}
            </nav>
          </div>
        </div>
      )}

      {/* Main content */}
      <div className="main-content">
        {/* Header */}
        <header className="header">
          <div className="header-left">
            <button
              className="mobile-menu-toggle"
              onClick={() => setMobileMenuOpen(true)}
            >
              ☰
            </button>
            <h1 className="page-title">
              {navigationItems.find(item => item.path === location.pathname)?.label || 'Dashboard'}
            </h1>
          </div>

          <div className="header-right">
            <div className="user-menu">
              <div className="user-info">
                <span className="user-name">{user?.username || 'User'}</span>
                <span className="user-role">{user?.role || 'Admin'}</span>
              </div>
              <button className="logout-btn" onClick={handleLogout} title="Logout">
                🚪
              </button>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="page-content">
          {children}
        </main>
      </div>
    </div>
  );
};

export default Layout;
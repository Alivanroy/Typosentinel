import React, { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import Layout from './components/Layout/Layout';
import Dashboard from './pages/Dashboard/Dashboard';
import ScanResults from './pages/ScanResults/ScanResults';
import ThreatAnalysis from './pages/ThreatAnalysis/ThreatAnalysis';
import Reports from './pages/Reports/Reports';
import Settings from './pages/Settings/Settings';
import Documentation from './pages/Documentation/Documentation';
import Login from './pages/Login/Login';
import { setAuthenticated } from './store/slices/authSlice';
import './App.css';

function AppContent() {
  const dispatch = useDispatch();
  const isAuthenticated = useSelector(state => state.auth.isAuthenticated);

  useEffect(() => {
    // Check if user is already logged in on app initialization
    const token = localStorage.getItem('typosentinel-token');
    if (token) {
      dispatch(setAuthenticated(true));
    }
  }, [dispatch]);

  if (!isAuthenticated) {
    return <Login />;
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan-results" element={<ScanResults />} />
        <Route path="/threat-analysis" element={<ThreatAnalysis />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/documentation" element={<Documentation />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  );
}

function App() {
  return (
    <div className="App">
      <AppContent />
    </div>
  );
}

export default App;
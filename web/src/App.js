import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Provider } from 'react-redux';
import { store } from './store/store';
import Layout from './components/Layout/Layout';
import Dashboard from './pages/Dashboard/Dashboard';
import ScanResults from './pages/ScanResults/ScanResults';
import ThreatAnalysis from './pages/ThreatAnalysis/ThreatAnalysis';
import Reports from './pages/Reports/Reports';
import Settings from './pages/Settings/Settings';
import Login from './pages/Login/Login';
import { useSelector } from 'react-redux';
import './App.css';

function AppContent() {
  const isAuthenticated = useSelector(state => state.auth.isAuthenticated);

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
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  );
}

function App() {
  return (
    <Provider store={store}>
      <Router>
        <div className="App">
          <AppContent />
        </div>
      </Router>
    </Provider>
  );
}

export default App;
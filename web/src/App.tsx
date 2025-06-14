import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { Box } from '@mui/material';

// Enterprise Management Views
import EnterpriseLayout from './components/enterprise/EnterpriseLayout';
import ExecutiveDashboard from './pages/enterprise/ExecutiveDashboard';
import VulnerabilityManagement from './pages/enterprise/VulnerabilityManagement';
import SupplyChainView from './pages/enterprise/SupplyChainView';
import PolicyManagement from './pages/enterprise/PolicyManagement';
import PolicyEditor from './pages/enterprise/PolicyEditor';
import PolicyPlayground from './pages/enterprise/PolicyPlayground';

// CLI/Extension Integration Views
import CLIIntegration from './pages/integration/CLIIntegration';
import VSCodeExtension from './pages/integration/VSCodeExtension';
import ScanResults from './pages/integration/ScanResults';

// Authentication & Common
import Login from './pages/auth/Login';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { SocketProvider } from './contexts/SocketContext';
import LoadingSpinner from './components/common/LoadingSpinner';

// Theme configuration
const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
      dark: '#115293',
      light: '#42a5f5',
    },
    secondary: {
      main: '#dc004e',
    },
    background: {
      default: '#f5f5f5',
      paper: '#ffffff',
    },
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontSize: '2.5rem',
      fontWeight: 600,
    },
    h2: {
      fontSize: '2rem',
      fontWeight: 600,
    },
    h3: {
      fontSize: '1.75rem',
      fontWeight: 600,
    },
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          borderRadius: 8,
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        },
      },
    },
  },
});

const AppContent: React.FC = () => {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingSpinner />;
  }

  if (!user) {
    return <Login />;
  }

  return (
    <Router>
      <Routes>
        {/* Enterprise Management Routes */}
        <Route path="/enterprise" element={<EnterpriseLayout />}>
          <Route index element={<Navigate to="/enterprise/dashboard" replace />} />
          <Route path="dashboard" element={<ExecutiveDashboard />} />
          <Route path="vulnerabilities" element={<VulnerabilityManagement />} />
          <Route path="supply-chain" element={<SupplyChainView />} />
          <Route path="policies" element={<PolicyManagement />} />
          <Route path="policies/editor" element={<PolicyEditor />} />
          <Route path="policies/playground" element={<PolicyPlayground />} />
        </Route>

        {/* CLI/Extension Integration Routes */}
        <Route path="/integration">
          <Route path="cli" element={<CLIIntegration />} />
          <Route path="vscode" element={<VSCodeExtension />} />
          <Route path="results/:scanId" element={<ScanResults />} />
        </Route>

        {/* Default redirect to enterprise dashboard */}
        <Route path="/" element={<Navigate to="/enterprise/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/enterprise/dashboard" replace />} />
      </Routes>
    </Router>
  );
};

const App: React.FC = () => {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AuthProvider>
        <SocketProvider>
          <Box sx={{ minHeight: '100vh', bgcolor: 'background.default' }}>
            <AppContent />
          </Box>
        </SocketProvider>
      </AuthProvider>
    </ThemeProvider>
  );
};

export default App;
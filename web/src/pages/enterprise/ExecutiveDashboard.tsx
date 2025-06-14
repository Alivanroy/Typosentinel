import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Alert,
  AlertTitle,
} from '@mui/material';
import {
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Visibility as VisibilityIcon,
  GetApp as DownloadIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, Legend } from 'recharts';
import { useSocket } from '../../contexts/SocketContext';
import { useNavigate } from 'react-router-dom';

interface DashboardMetrics {
  totalScans: number;
  vulnerabilitiesFound: number;
  packagesScanned: number;
  riskScore: number;
  trendsData: Array<{
    date: string;
    scans: number;
    vulnerabilities: number;
    riskScore: number;
  }>;
  vulnerabilityBreakdown: Array<{
    severity: string;
    count: number;
    color: string;
  }>;
  recentFindings: Array<{
    id: string;
    packageName: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    type: string;
    timestamp: Date;
    source: 'cli' | 'vscode' | 'api';
  }>;
  topRiskyPackages: Array<{
    name: string;
    riskScore: number;
    vulnerabilities: number;
    downloads: number;
  }>;
}

const ExecutiveDashboard: React.FC = () => {
  const navigate = useNavigate();
  const { scanEvents } = useSocket();
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      // Simulate API call - replace with actual API
      const mockData: DashboardMetrics = {
        totalScans: 1247,
        vulnerabilitiesFound: 89,
        packagesScanned: 15623,
        riskScore: 7.2,
        trendsData: [
          { date: '2025-06-10', scans: 45, vulnerabilities: 12, riskScore: 6.8 },
          { date: '2025-06-11', scans: 52, vulnerabilities: 15, riskScore: 7.1 },
          { date: '2025-06-12', scans: 38, vulnerabilities: 8, riskScore: 6.5 },
          { date: '2025-06-13', scans: 61, vulnerabilities: 18, riskScore: 7.8 },
          { date: '2025-06-14', scans: 47, vulnerabilities: 11, riskScore: 7.2 },
        ],
        vulnerabilityBreakdown: [
          { severity: 'Critical', count: 12, color: '#f44336' },
          { severity: 'High', count: 23, color: '#ff9800' },
          { severity: 'Medium', count: 34, color: '#ffeb3b' },
          { severity: 'Low', count: 20, color: '#4caf50' },
        ],
        recentFindings: [
          {
            id: '1',
            packageName: 'lodahs',
            severity: 'critical',
            type: 'Typosquatting',
            timestamp: new Date('2025-06-14T10:30:00'),
            source: 'cli',
          },
          {
            id: '2',
            packageName: 'crypto-miner-js',
            severity: 'high',
            type: 'Cryptocurrency Mining',
            timestamp: new Date('2025-06-14T09:15:00'),
            source: 'vscode',
          },
          {
            id: '3',
            packageName: 'data-exfil',
            severity: 'high',
            type: 'Data Exfiltration',
            timestamp: new Date('2025-06-14T08:45:00'),
            source: 'api',
          },
        ],
        topRiskyPackages: [
          { name: 'suspicious-package', riskScore: 9.2, vulnerabilities: 5, downloads: 1250 },
          { name: 'malware-lib', riskScore: 8.8, vulnerabilities: 3, downloads: 890 },
          { name: 'typo-lodash', riskScore: 8.5, vulnerabilities: 2, downloads: 2100 },
          { name: 'crypto-stealer', riskScore: 8.1, vulnerabilities: 4, downloads: 567 },
        ],
      };
      
      setMetrics(mockData);
      setLastUpdated(new Date());
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 8) return 'error';
    if (score >= 6) return 'warning';
    if (score >= 4) return 'info';
    return 'success';
  };

  if (loading || !metrics) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography variant="h4" gutterBottom>Executive Dashboard</Typography>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Executive Dashboard
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Last updated: {lastUpdated.toLocaleString()}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh data">
            <IconButton onClick={loadDashboardData}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          <Button 
            variant="outlined" 
            startIcon={<DownloadIcon />}
            onClick={() => {
              // Handle export functionality
              console.log('Export dashboard data');
            }}
          >
            Export Report
          </Button>
        </Box>
      </Box>

      {/* Key Metrics Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Total Scans
                  </Typography>
                  <Typography variant="h4">
                    {metrics.totalScans.toLocaleString()}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                    <TrendingUpIcon color="success" fontSize="small" />
                    <Typography variant="body2" color="success.main" sx={{ ml: 0.5 }}>
                      +12% from last week
                    </Typography>
                  </Box>
                </Box>
                <SecurityIcon color="primary" sx={{ fontSize: 40 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Vulnerabilities Found
                  </Typography>
                  <Typography variant="h4" color="error.main">
                    {metrics.vulnerabilitiesFound}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                    <TrendingDownIcon color="success" fontSize="small" />
                    <Typography variant="body2" color="success.main" sx={{ ml: 0.5 }}>
                      -8% from last week
                    </Typography>
                  </Box>
                </Box>
                <WarningIcon color="error" sx={{ fontSize: 40 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Packages Scanned
                  </Typography>
                  <Typography variant="h4">
                    {metrics.packagesScanned.toLocaleString()}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                    <TrendingUpIcon color="success" fontSize="small" />
                    <Typography variant="body2" color="success.main" sx={{ ml: 0.5 }}>
                      +25% from last week
                    </Typography>
                  </Box>
                </Box>
                <CheckCircleIcon color="success" sx={{ fontSize: 40 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Risk Score
                  </Typography>
                  <Typography variant="h4" color={`${getRiskScoreColor(metrics.riskScore)}.main`}>
                    {metrics.riskScore}/10
                  </Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={metrics.riskScore * 10} 
                    color={getRiskScoreColor(metrics.riskScore)}
                    sx={{ mt: 1, height: 6, borderRadius: 3 }}
                  />
                </Box>
                <ErrorIcon color={getRiskScoreColor(metrics.riskScore)} sx={{ fontSize: 40 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Critical Alerts */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12}>
          <Alert severity="warning" sx={{ mb: 2 }}>
            <AlertTitle>Critical Security Alert</AlertTitle>
            12 critical vulnerabilities detected in the last 24 hours. Immediate action required.
            <Button 
              size="small" 
              sx={{ ml: 2 }}
              onClick={() => navigate('/enterprise/vulnerabilities')}
            >
              View Details
            </Button>
          </Alert>
        </Grid>
      </Grid>

      {/* Charts and Analytics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Security Trends (Last 7 Days)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={metrics.trendsData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis yAxisId="left" />
                  <YAxis yAxisId="right" orientation="right" />
                  <RechartsTooltip />
                  <Legend />
                  <Line 
                    yAxisId="left" 
                    type="monotone" 
                    dataKey="scans" 
                    stroke="#1976d2" 
                    strokeWidth={2}
                    name="Scans"
                  />
                  <Line 
                    yAxisId="left" 
                    type="monotone" 
                    dataKey="vulnerabilities" 
                    stroke="#f44336" 
                    strokeWidth={2}
                    name="Vulnerabilities"
                  />
                  <Line 
                    yAxisId="right" 
                    type="monotone" 
                    dataKey="riskScore" 
                    stroke="#ff9800" 
                    strokeWidth={2}
                    name="Risk Score"
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Vulnerability Breakdown
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={metrics.vulnerabilityBreakdown}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="count"
                  >
                    {metrics.vulnerabilityBreakdown.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Recent Findings and Top Risky Packages */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6">
                  Recent Security Findings
                </Typography>
                <Button 
                  size="small" 
                  onClick={() => navigate('/enterprise/vulnerabilities')}
                >
                  View All
                </Button>
              </Box>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Package</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Source</TableCell>
                      <TableCell>Time</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {metrics.recentFindings.map((finding) => (
                      <TableRow key={finding.id}>
                        <TableCell>
                          <Typography variant="body2" fontWeight={500}>
                            {finding.packageName}
                          </Typography>
                        </TableCell>
                        <TableCell>{finding.type}</TableCell>
                        <TableCell>
                          <Chip 
                            label={finding.severity.toUpperCase()} 
                            color={getSeverityColor(finding.severity) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={finding.source.toUpperCase()} 
                            variant="outlined"
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {finding.timestamp.toLocaleTimeString()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Tooltip title="View details">
                            <IconButton 
                              size="small"
                              onClick={() => navigate(`/integration/results/${finding.id}`)}
                            >
                              <VisibilityIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Top Risky Packages
              </Typography>
              {metrics.topRiskyPackages.map((pkg, index) => (
                <Box 
                  key={pkg.name}
                  sx={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center',
                    py: 1,
                    borderBottom: index < metrics.topRiskyPackages.length - 1 ? '1px solid' : 'none',
                    borderColor: 'divider',
                  }}
                >
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="body2" fontWeight={500}>
                      {pkg.name}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {pkg.vulnerabilities} vulnerabilities • {pkg.downloads.toLocaleString()} downloads
                    </Typography>
                  </Box>
                  <Chip 
                    label={pkg.riskScore.toFixed(1)} 
                    color={getRiskScoreColor(pkg.riskScore) as any}
                    size="small"
                  />
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ExecutiveDashboard;
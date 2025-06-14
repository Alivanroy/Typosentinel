import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tabs,
  Tab,
  LinearProgress,
  Alert,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemAvatar,
  Avatar,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  AccountTree as DependencyIcon,
  Timeline as TimelineIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Shield as ShieldIcon,
  BugReport as VulnerabilityIcon,
  Update as UpdateIcon,
  GetApp as DownloadIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
  Search as SearchIcon,
  Visibility as ViewIcon,
  Link as LinkIcon,
  Code as CodeIcon,
  Storage as PackageIcon,
  CloudDownload as RegistryIcon,
} from '@mui/icons-material';
import { 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip as RechartsTooltip, 
  ResponsiveContainer, 
  LineChart, 
  Line,
  TreeMap,
  Sankey,
} from 'recharts';

interface Dependency {
  id: string;
  name: string;
  version: string;
  ecosystem: 'npm' | 'pypi' | 'maven' | 'nuget' | 'rubygems';
  type: 'direct' | 'transitive';
  depth: number;
  parent?: string;
  children: string[];
  riskScore: number;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  licenses: string[];
  maintainer: {
    name: string;
    email?: string;
    verified: boolean;
  };
  repository: {
    url: string;
    stars: number;
    forks: number;
    lastCommit: Date;
  };
  downloads: {
    weekly: number;
    monthly: number;
    total: number;
  };
  age: {
    created: Date;
    lastUpdate: Date;
  };
  integrity: {
    checksumVerified: boolean;
    signatureVerified: boolean;
    reproducibleBuild: boolean;
  };
  compliance: {
    licenseCompatible: boolean;
    securityPolicy: boolean;
    codeOfConduct: boolean;
  };
}

interface Project {
  id: string;
  name: string;
  description: string;
  ecosystem: string;
  dependencies: Dependency[];
  riskScore: number;
  lastScan: Date;
  status: 'healthy' | 'warning' | 'critical';
}

interface SupplyChainRisk {
  id: string;
  type: 'abandoned' | 'typosquatting' | 'malicious' | 'outdated' | 'license' | 'maintainer';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  affectedPackages: string[];
  recommendation: string;
  discoveredAt: Date;
}

const SupplyChainDashboard: React.FC = () => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [dependencies, setDependencies] = useState<Dependency[]>([]);
  const [risks, setRisks] = useState<SupplyChainRisk[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTab, setSelectedTab] = useState(0);
  const [selectedProject, setSelectedProject] = useState<string>('all');
  const [filterEcosystem, setFilterEcosystem] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [dependencyDialogOpen, setDependencyDialogOpen] = useState(false);
  const [selectedDependency, setSelectedDependency] = useState<Dependency | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      // Simulate API calls - replace with actual APIs
      const mockProjects: Project[] = [
        {
          id: '1',
          name: 'Web Frontend',
          description: 'React-based web application',
          ecosystem: 'npm',
          dependencies: [],
          riskScore: 7.2,
          lastScan: new Date('2025-06-14T10:30:00'),
          status: 'warning',
        },
        {
          id: '2',
          name: 'API Gateway',
          description: 'Node.js API gateway service',
          ecosystem: 'npm',
          dependencies: [],
          riskScore: 4.1,
          lastScan: new Date('2025-06-14T09:15:00'),
          status: 'healthy',
        },
        {
          id: '3',
          name: 'ML Pipeline',
          description: 'Python machine learning pipeline',
          ecosystem: 'pypi',
          dependencies: [],
          riskScore: 8.9,
          lastScan: new Date('2025-06-14T08:45:00'),
          status: 'critical',
        },
      ];

      const mockDependencies: Dependency[] = [
        {
          id: '1',
          name: 'lodash',
          version: '4.17.21',
          ecosystem: 'npm',
          type: 'direct',
          depth: 1,
          children: [],
          riskScore: 2.1,
          vulnerabilities: { critical: 0, high: 0, medium: 1, low: 2 },
          licenses: ['MIT'],
          maintainer: {
            name: 'John-David Dalton',
            email: 'john.david.dalton@gmail.com',
            verified: true,
          },
          repository: {
            url: 'https://github.com/lodash/lodash',
            stars: 59000,
            forks: 7000,
            lastCommit: new Date('2025-05-15'),
          },
          downloads: {
            weekly: 45000000,
            monthly: 180000000,
            total: 2500000000,
          },
          age: {
            created: new Date('2012-04-23'),
            lastUpdate: new Date('2021-02-20'),
          },
          integrity: {
            checksumVerified: true,
            signatureVerified: true,
            reproducibleBuild: true,
          },
          compliance: {
            licenseCompatible: true,
            securityPolicy: true,
            codeOfConduct: true,
          },
        },
        {
          id: '2',
          name: 'express',
          version: '4.16.1',
          ecosystem: 'npm',
          type: 'direct',
          depth: 1,
          children: ['accepts', 'array-flatten', 'body-parser'],
          riskScore: 6.8,
          vulnerabilities: { critical: 0, high: 2, medium: 3, low: 1 },
          licenses: ['MIT'],
          maintainer: {
            name: 'Douglas Christopher Wilson',
            email: 'doug@somethingdoug.com',
            verified: true,
          },
          repository: {
            url: 'https://github.com/expressjs/express',
            stars: 65000,
            forks: 15000,
            lastCommit: new Date('2025-06-10'),
          },
          downloads: {
            weekly: 25000000,
            monthly: 100000000,
            total: 1800000000,
          },
          age: {
            created: new Date('2009-06-26'),
            lastUpdate: new Date('2018-10-10'),
          },
          integrity: {
            checksumVerified: true,
            signatureVerified: false,
            reproducibleBuild: false,
          },
          compliance: {
            licenseCompatible: true,
            securityPolicy: true,
            codeOfConduct: true,
          },
        },
        {
          id: '3',
          name: 'suspicious-package',
          version: '1.0.0',
          ecosystem: 'npm',
          type: 'transitive',
          depth: 3,
          parent: 'some-dependency',
          children: [],
          riskScore: 9.2,
          vulnerabilities: { critical: 2, high: 1, medium: 0, low: 0 },
          licenses: ['Unknown'],
          maintainer: {
            name: 'anonymous',
            verified: false,
          },
          repository: {
            url: 'https://github.com/fake/suspicious-package',
            stars: 5,
            forks: 0,
            lastCommit: new Date('2025-06-01'),
          },
          downloads: {
            weekly: 1200,
            monthly: 4800,
            total: 15000,
          },
          age: {
            created: new Date('2025-05-20'),
            lastUpdate: new Date('2025-06-01'),
          },
          integrity: {
            checksumVerified: false,
            signatureVerified: false,
            reproducibleBuild: false,
          },
          compliance: {
            licenseCompatible: false,
            securityPolicy: false,
            codeOfConduct: false,
          },
        },
        {
          id: '4',
          name: 'tensorflow',
          version: '2.13.0',
          ecosystem: 'pypi',
          type: 'direct',
          depth: 1,
          children: ['numpy', 'protobuf', 'grpcio'],
          riskScore: 3.4,
          vulnerabilities: { critical: 0, high: 0, medium: 2, low: 5 },
          licenses: ['Apache-2.0'],
          maintainer: {
            name: 'Google',
            email: 'tensorflow@google.com',
            verified: true,
          },
          repository: {
            url: 'https://github.com/tensorflow/tensorflow',
            stars: 185000,
            forks: 74000,
            lastCommit: new Date('2025-06-13'),
          },
          downloads: {
            weekly: 8000000,
            monthly: 32000000,
            total: 500000000,
          },
          age: {
            created: new Date('2015-11-09'),
            lastUpdate: new Date('2023-08-11'),
          },
          integrity: {
            checksumVerified: true,
            signatureVerified: true,
            reproducibleBuild: true,
          },
          compliance: {
            licenseCompatible: true,
            securityPolicy: true,
            codeOfConduct: true,
          },
        },
      ];

      const mockRisks: SupplyChainRisk[] = [
        {
          id: '1',
          type: 'malicious',
          severity: 'critical',
          title: 'Malicious Package Detected',
          description: 'The package "suspicious-package" contains code that attempts to exfiltrate environment variables and send them to an external server.',
          affectedPackages: ['suspicious-package@1.0.0'],
          recommendation: 'Remove this package immediately and audit all systems that may have been exposed.',
          discoveredAt: new Date('2025-06-14T11:30:00'),
        },
        {
          id: '2',
          type: 'outdated',
          severity: 'high',
          title: 'Outdated Express.js Version',
          description: 'Express.js version 4.16.1 is significantly outdated and contains known security vulnerabilities.',
          affectedPackages: ['express@4.16.1'],
          recommendation: 'Upgrade to Express.js version 4.18.2 or later to address security vulnerabilities.',
          discoveredAt: new Date('2025-06-14T09:15:00'),
        },
        {
          id: '3',
          type: 'license',
          severity: 'medium',
          title: 'License Compatibility Issue',
          description: 'Package "suspicious-package" has an unknown license that may not be compatible with your project\'s licensing requirements.',
          affectedPackages: ['suspicious-package@1.0.0'],
          recommendation: 'Review the package license and consider finding an alternative with a compatible license.',
          discoveredAt: new Date('2025-06-14T10:00:00'),
        },
        {
          id: '4',
          type: 'maintainer',
          severity: 'medium',
          title: 'Unverified Package Maintainer',
          description: 'The maintainer of "suspicious-package" is not verified and has limited reputation in the ecosystem.',
          affectedPackages: ['suspicious-package@1.0.0'],
          recommendation: 'Consider using packages from verified maintainers or well-established organizations.',
          discoveredAt: new Date('2025-06-14T10:15:00'),
        },
      ];

      setProjects(mockProjects);
      setDependencies(mockDependencies);
      setRisks(mockRisks);
    } catch (error) {
      console.error('Failed to load supply chain data:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredDependencies = dependencies.filter(dep => {
    const matchesEcosystem = filterEcosystem === 'all' || dep.ecosystem === filterEcosystem;
    const matchesSearch = searchTerm === '' || 
      dep.name.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesEcosystem && matchesSearch;
  });

  const getRiskColor = (riskScore: number) => {
    if (riskScore >= 8) return '#d32f2f';
    if (riskScore >= 6) return '#f57c00';
    if (riskScore >= 4) return '#1976d2';
    return '#388e3c';
  };

  const getRiskLevel = (riskScore: number) => {
    if (riskScore >= 8) return 'Critical';
    if (riskScore >= 6) return 'High';
    if (riskScore >= 4) return 'Medium';
    return 'Low';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f57c00';
      case 'medium': return '#1976d2';
      case 'low': return '#388e3c';
      default: return '#757575';
    }
  };

  const getEcosystemIcon = (ecosystem: string) => {
    switch (ecosystem) {
      case 'npm': return <CodeIcon />;
      case 'pypi': return <PackageIcon />;
      case 'maven': return <RegistryIcon />;
      default: return <PackageIcon />;
    }
  };

  // Statistics
  const stats = {
    totalDependencies: dependencies.length,
    directDependencies: dependencies.filter(d => d.type === 'direct').length,
    transitiveDependencies: dependencies.filter(d => d.type === 'transitive').length,
    highRiskDependencies: dependencies.filter(d => d.riskScore >= 6).length,
    vulnerabilities: dependencies.reduce((sum, d) => sum + d.vulnerabilities.critical + d.vulnerabilities.high + d.vulnerabilities.medium + d.vulnerabilities.low, 0),
    criticalVulnerabilities: dependencies.reduce((sum, d) => sum + d.vulnerabilities.critical, 0),
    unverifiedMaintainers: dependencies.filter(d => !d.maintainer.verified).length,
    outdatedPackages: dependencies.filter(d => {
      const daysSinceUpdate = (Date.now() - d.age.lastUpdate.getTime()) / (1000 * 60 * 60 * 24);
      return daysSinceUpdate > 365;
    }).length,
  };

  const ecosystemData = [
    { name: 'npm', value: dependencies.filter(d => d.ecosystem === 'npm').length, color: '#cb3837' },
    { name: 'PyPI', value: dependencies.filter(d => d.ecosystem === 'pypi').length, color: '#3776ab' },
    { name: 'Maven', value: dependencies.filter(d => d.ecosystem === 'maven').length, color: '#f89820' },
    { name: 'NuGet', value: dependencies.filter(d => d.ecosystem === 'nuget').length, color: '#004880' },
  ].filter(item => item.value > 0);

  const riskDistribution = [
    { name: 'Low (0-4)', value: dependencies.filter(d => d.riskScore < 4).length, color: '#388e3c' },
    { name: 'Medium (4-6)', value: dependencies.filter(d => d.riskScore >= 4 && d.riskScore < 6).length, color: '#1976d2' },
    { name: 'High (6-8)', value: dependencies.filter(d => d.riskScore >= 6 && d.riskScore < 8).length, color: '#f57c00' },
    { name: 'Critical (8+)', value: dependencies.filter(d => d.riskScore >= 8).length, color: '#d32f2f' },
  ];

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          Supply Chain Dashboard
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button variant="outlined" startIcon={<DownloadIcon />}>
            Export SBOM
          </Button>
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={loadData}>
            Refresh
          </Button>
        </Box>
      </Box>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={selectedTab} onChange={(_, newValue) => setSelectedTab(newValue)}>
          <Tab label="Overview" />
          <Tab label="Dependencies" />
          <Tab label="Risk Analysis" />
          <Tab label="Compliance" />
        </Tabs>
      </Box>

      {/* Overview Tab */}
      {selectedTab === 0 && (
        <Grid container spacing={3}>
          {/* Summary Cards */}
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom>
                      Total Dependencies
                    </Typography>
                    <Typography variant="h4">
                      {stats.totalDependencies}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {stats.directDependencies} direct, {stats.transitiveDependencies} transitive
                    </Typography>
                  </Box>
                  <DependencyIcon sx={{ fontSize: 40, color: 'primary.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom>
                      High Risk Packages
                    </Typography>
                    <Typography variant="h4" color="error.main">
                      {stats.highRiskDependencies}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Risk score ≥ 6.0
                    </Typography>
                  </Box>
                  <WarningIcon sx={{ fontSize: 40, color: 'error.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom>
                      Vulnerabilities
                    </Typography>
                    <Typography variant="h4" color="warning.main">
                      {stats.vulnerabilities}
                    </Typography>
                    <Typography variant="body2" color="error.main">
                      {stats.criticalVulnerabilities} critical
                    </Typography>
                  </Box>
                  <VulnerabilityIcon sx={{ fontSize: 40, color: 'warning.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom>
                      Outdated Packages
                    </Typography>
                    <Typography variant="h4" color="info.main">
                      {stats.outdatedPackages}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Not updated in 1+ year
                    </Typography>
                  </Box>
                  <UpdateIcon sx={{ fontSize: 40, color: 'info.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Charts */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Dependencies by Ecosystem
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={ecosystemData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {ecosystemData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Risk Score Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={riskDistribution}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="value" fill={(entry: any) => entry.color} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>

          {/* Project Status */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Project Status
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Project</TableCell>
                        <TableCell>Ecosystem</TableCell>
                        <TableCell>Risk Score</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Last Scan</TableCell>
                        <TableCell>Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {projects.map((project) => (
                        <TableRow key={project.id}>
                          <TableCell>
                            <Box>
                              <Typography variant="body2" fontWeight={500}>
                                {project.name}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                {project.description}
                              </Typography>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              {getEcosystemIcon(project.ecosystem)}
                              <Typography variant="body2" sx={{ ml: 1 }}>
                                {project.ecosystem.toUpperCase()}
                              </Typography>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              <Typography 
                                variant="body2" 
                                sx={{ 
                                  color: getRiskColor(project.riskScore),
                                  fontWeight: 'bold'
                                }}
                              >
                                {project.riskScore.toFixed(1)}
                              </Typography>
                              <Typography variant="caption" sx={{ ml: 1 }}>
                                ({getRiskLevel(project.riskScore)})
                              </Typography>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={project.status} 
                              color={
                                project.status === 'healthy' ? 'success' :
                                project.status === 'warning' ? 'warning' : 'error'
                              }
                              size="small"
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2">
                              {project.lastScan.toLocaleDateString()}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Button size="small" variant="outlined">
                              View Details
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Dependencies Tab */}
      {selectedTab === 1 && (
        <Box>
          {/* Filters */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Grid container spacing={2} alignItems="center">
                <Grid item xs={12} md={4}>
                  <TextField
                    fullWidth
                    placeholder="Search dependencies..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    InputProps={{
                      startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                    }}
                  />
                </Grid>
                <Grid item xs={12} md={3}>
                  <FormControl fullWidth>
                    <InputLabel>Ecosystem</InputLabel>
                    <Select
                      value={filterEcosystem}
                      label="Ecosystem"
                      onChange={(e) => setFilterEcosystem(e.target.value)}
                    >
                      <MenuItem value="all">All Ecosystems</MenuItem>
                      <MenuItem value="npm">npm</MenuItem>
                      <MenuItem value="pypi">PyPI</MenuItem>
                      <MenuItem value="maven">Maven</MenuItem>
                      <MenuItem value="nuget">NuGet</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} md={3}>
                  <FormControl fullWidth>
                    <InputLabel>Project</InputLabel>
                    <Select
                      value={selectedProject}
                      label="Project"
                      onChange={(e) => setSelectedProject(e.target.value)}
                    >
                      <MenuItem value="all">All Projects</MenuItem>
                      {projects.map((project) => (
                        <MenuItem key={project.id} value={project.id}>
                          {project.name}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} md={2}>
                  <Typography variant="body2" color="text.secondary">
                    {filteredDependencies.length} dependencies
                  </Typography>
                </Grid>
              </Grid>
            </CardContent>
          </Card>

          {/* Dependencies Table */}
          <Card>
            <CardContent>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Package</TableCell>
                      <TableCell>Version</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Risk Score</TableCell>
                      <TableCell>Vulnerabilities</TableCell>
                      <TableCell>License</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {filteredDependencies.map((dep) => (
                      <TableRow key={dep.id} hover>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            {getEcosystemIcon(dep.ecosystem)}
                            <Box sx={{ ml: 1 }}>
                              <Typography variant="body2" fontWeight={500}>
                                {dep.name}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                {dep.ecosystem} • {dep.downloads.weekly.toLocaleString()} weekly downloads
                              </Typography>
                            </Box>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {dep.version}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={dep.type} 
                            variant="outlined"
                            size="small"
                            color={dep.type === 'direct' ? 'primary' : 'default'}
                          />
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                color: getRiskColor(dep.riskScore),
                                fontWeight: 'bold'
                              }}
                            >
                              {dep.riskScore.toFixed(1)}
                            </Typography>
                            <Typography variant="caption" sx={{ ml: 1 }}>
                              ({getRiskLevel(dep.riskScore)})
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5 }}>
                            {dep.vulnerabilities.critical > 0 && (
                              <Chip 
                                label={`${dep.vulnerabilities.critical}C`} 
                                size="small"
                                sx={{ backgroundColor: '#d32f2f', color: 'white', fontSize: '0.7rem' }}
                              />
                            )}
                            {dep.vulnerabilities.high > 0 && (
                              <Chip 
                                label={`${dep.vulnerabilities.high}H`} 
                                size="small"
                                sx={{ backgroundColor: '#f57c00', color: 'white', fontSize: '0.7rem' }}
                              />
                            )}
                            {dep.vulnerabilities.medium > 0 && (
                              <Chip 
                                label={`${dep.vulnerabilities.medium}M`} 
                                size="small"
                                sx={{ backgroundColor: '#1976d2', color: 'white', fontSize: '0.7rem' }}
                              />
                            )}
                            {dep.vulnerabilities.low > 0 && (
                              <Chip 
                                label={`${dep.vulnerabilities.low}L`} 
                                size="small"
                                sx={{ backgroundColor: '#388e3c', color: 'white', fontSize: '0.7rem' }}
                              />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.5 }}>
                            {dep.licenses.map((license, index) => (
                              <Chip 
                                key={index}
                                label={license} 
                                variant="outlined"
                                size="small"
                                color={dep.compliance.licenseCompatible ? 'success' : 'error'}
                              />
                            ))}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Button 
                            size="small" 
                            variant="outlined"
                            onClick={() => {
                              setSelectedDependency(dep);
                              setDependencyDialogOpen(true);
                            }}
                          >
                            Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Box>
      )}

      {/* Risk Analysis Tab */}
      {selectedTab === 2 && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Supply Chain Risks
                </Typography>
                <List>
                  {risks.map((risk) => (
                    <ListItem key={risk.id} divider>
                      <ListItemAvatar>
                        <Avatar sx={{ backgroundColor: getSeverityColor(risk.severity) }}>
                          {risk.severity === 'critical' ? <ErrorIcon /> : 
                           risk.severity === 'high' ? <WarningIcon /> : 
                           <SecurityIcon />}
                        </Avatar>
                      </ListItemAvatar>
                      <ListItemText
                        primary={risk.title}
                        secondary={
                          <Box>
                            <Typography variant="body2" color="text.secondary">
                              {risk.description}
                            </Typography>
                            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                              <Chip 
                                label={risk.type} 
                                variant="outlined"
                                size="small"
                              />
                              <Chip 
                                label={risk.severity.toUpperCase()} 
                                sx={{ 
                                  backgroundColor: getSeverityColor(risk.severity),
                                  color: 'white'
                                }}
                                size="small"
                              />
                              <Typography variant="caption" sx={{ alignSelf: 'center' }}>
                                Affects: {risk.affectedPackages.join(', ')}
                              </Typography>
                            </Box>
                          </Box>
                        }
                      />
                      <Button size="small" variant="outlined">
                        View Details
                      </Button>
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Compliance Tab */}
      {selectedTab === 3 && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  License Compliance
                </Typography>
                <Typography variant="h4" color="success.main">
                  {Math.round((dependencies.filter(d => d.compliance.licenseCompatible).length / dependencies.length) * 100)}%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Compatible licenses
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Security Policies
                </Typography>
                <Typography variant="h4" color="warning.main">
                  {Math.round((dependencies.filter(d => d.compliance.securityPolicy).length / dependencies.length) * 100)}%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Have security policies
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Verified Maintainers
                </Typography>
                <Typography variant="h4" color="info.main">
                  {Math.round((dependencies.filter(d => d.maintainer.verified).length / dependencies.length) * 100)}%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Verified maintainers
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Dependency Details Dialog */}
      <Dialog 
        open={dependencyDialogOpen} 
        onClose={() => setDependencyDialogOpen(false)} 
        maxWidth="md" 
        fullWidth
      >
        {selectedDependency && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {getEcosystemIcon(selectedDependency.ecosystem)}
                {selectedDependency.name}@{selectedDependency.version}
              </Box>
            </DialogTitle>
            <DialogContent>
              <Grid container spacing={2} sx={{ mb: 2 }}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Risk Score
                  </Typography>
                  <Typography 
                    variant="h6" 
                    sx={{ color: getRiskColor(selectedDependency.riskScore) }}
                  >
                    {selectedDependency.riskScore.toFixed(1)} ({getRiskLevel(selectedDependency.riskScore)})
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Weekly Downloads
                  </Typography>
                  <Typography variant="h6">
                    {selectedDependency.downloads.weekly.toLocaleString()}
                  </Typography>
                </Grid>
              </Grid>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography>Repository Information</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Stars
                      </Typography>
                      <Typography variant="body1">
                        {selectedDependency.repository.stars.toLocaleString()}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="text.secondary">
                        Forks
                      </Typography>
                      <Typography variant="body1">
                        {selectedDependency.repository.forks.toLocaleString()}
                      </Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">
                        Repository URL
                      </Typography>
                      <Typography variant="body1">
                        <a href={selectedDependency.repository.url} target="_blank" rel="noopener noreferrer">
                          {selectedDependency.repository.url}
                        </a>
                      </Typography>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography>Security & Compliance</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={4}>
                      <Typography variant="body2" color="text.secondary">
                        Checksum Verified
                      </Typography>
                      <Chip 
                        label={selectedDependency.integrity.checksumVerified ? 'Yes' : 'No'}
                        color={selectedDependency.integrity.checksumVerified ? 'success' : 'error'}
                        size="small"
                      />
                    </Grid>
                    <Grid item xs={4}>
                      <Typography variant="body2" color="text.secondary">
                        Signature Verified
                      </Typography>
                      <Chip 
                        label={selectedDependency.integrity.signatureVerified ? 'Yes' : 'No'}
                        color={selectedDependency.integrity.signatureVerified ? 'success' : 'error'}
                        size="small"
                      />
                    </Grid>
                    <Grid item xs={4}>
                      <Typography variant="body2" color="text.secondary">
                        Reproducible Build
                      </Typography>
                      <Chip 
                        label={selectedDependency.integrity.reproducibleBuild ? 'Yes' : 'No'}
                        color={selectedDependency.integrity.reproducibleBuild ? 'success' : 'error'}
                        size="small"
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDependencyDialogOpen(false)}>Close</Button>
              <Button variant="contained">View Vulnerabilities</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
};

export default SupplyChainDashboard;
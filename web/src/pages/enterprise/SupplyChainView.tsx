import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Tabs,
  Tab,
  Paper,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Switch,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
  Breadcrumbs,
  Link,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  LinearProgress,
  InputAdornment,
  ListItemIcon
} from '@mui/material';
import {
  Search as SearchIcon,
  FilterList as FilterIcon,
  Visibility as ViewIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckIcon,
  Info as InfoIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  Timeline as TimelineIcon,
  Security as SecurityIcon,
  AccountTree as DependencyIcon,
  Assessment as AssessmentIcon,
  ExpandMore as ExpandMoreIcon,
  BugReport as BugIcon,
  Shield as ShieldIcon,
  Speed as SpeedIcon
} from '@mui/icons-material';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts';

interface Package {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  riskScore: number;
  vulnerabilities: number;
  licenses: string[];
  maintainer: string;
  lastUpdated: Date;
  downloads: number;
  dependencies: number;
  status: 'safe' | 'warning' | 'critical';
  compliance: {
    license: boolean;
    security: boolean;
    maintainer: boolean;
  };
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`supply-chain-tabpanel-${index}`}
      aria-labelledby={`supply-chain-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

const SupplyChainView: React.FC = () => {
  const [packages, setPackages] = useState<Package[]>([]);
  const [filteredPackages, setFilteredPackages] = useState<Package[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEcosystem, setSelectedEcosystem] = useState('all');
  const [selectedRisk, setSelectedRisk] = useState('all');
  const [selectedPackage, setSelectedPackage] = useState<Package | null>(null);
  const [packageDialogOpen, setPackageDialogOpen] = useState(false);
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(true);

  // Mock data
  useEffect(() => {
    const mockPackages: Package[] = [
      {
        id: '1',
        name: 'react',
        version: '18.2.0',
        ecosystem: 'npm',
        riskScore: 2,
        vulnerabilities: 0,
        licenses: ['MIT'],
        maintainer: 'React Team',
        lastUpdated: new Date('2023-06-14'),
        downloads: 20000000,
        dependencies: 3,
        status: 'safe',
        compliance: { license: true, security: true, maintainer: true }
      },
      {
        id: '2',
        name: 'lodash',
        version: '4.17.21',
        ecosystem: 'npm',
        riskScore: 6,
        vulnerabilities: 2,
        licenses: ['MIT'],
        maintainer: 'John-David Dalton',
        lastUpdated: new Date('2023-05-20'),
        downloads: 50000000,
        dependencies: 0,
        status: 'warning',
        compliance: { license: true, security: false, maintainer: true }
      },
      {
        id: '3',
        name: 'express',
        version: '4.18.2',
        ecosystem: 'npm',
        riskScore: 4,
        vulnerabilities: 1,
        licenses: ['MIT'],
        maintainer: 'TJ Holowaychuk',
        lastUpdated: new Date('2023-06-10'),
        downloads: 30000000,
        dependencies: 31,
        status: 'warning',
        compliance: { license: true, security: true, maintainer: true }
      },
      {
        id: '4',
        name: 'requests',
        version: '2.31.0',
        ecosystem: 'pypi',
        riskScore: 3,
        vulnerabilities: 0,
        licenses: ['Apache-2.0'],
        maintainer: 'Kenneth Reitz',
        lastUpdated: new Date('2023-05-22'),
        downloads: 100000000,
        dependencies: 5,
        status: 'safe',
        compliance: { license: true, security: true, maintainer: true }
      },
      {
        id: '5',
        name: 'numpy',
        version: '1.24.3',
        ecosystem: 'pypi',
        riskScore: 8,
        vulnerabilities: 3,
        licenses: ['BSD-3-Clause'],
        maintainer: 'NumPy Developers',
        lastUpdated: new Date('2023-04-15'),
        downloads: 80000000,
        dependencies: 0,
        status: 'critical',
        compliance: { license: true, security: false, maintainer: false }
      }
    ];

    setTimeout(() => {
      setPackages(mockPackages);
      setFilteredPackages(mockPackages);
      setLoading(false);
    }, 1000);
  }, []);

  // Filter packages
  useEffect(() => {
    let filtered = packages.filter(pkg => {
      const matchesSearch = pkg.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           pkg.maintainer.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesEcosystem = selectedEcosystem === 'all' || pkg.ecosystem === selectedEcosystem;
      const matchesRisk = selectedRisk === 'all' || pkg.status === selectedRisk;
      
      return matchesSearch && matchesEcosystem && matchesRisk;
    });
    
    setFilteredPackages(filtered);
  }, [packages, searchTerm, selectedEcosystem, selectedRisk]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handlePackageClick = (pkg: Package) => {
    setSelectedPackage(pkg);
    setPackageDialogOpen(true);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'safe': return 'success';
      case 'warning': return 'warning';
      case 'critical': return 'error';
      default: return 'default';
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score <= 3) return '#4caf50';
    if (score <= 6) return '#ff9800';
    return '#f44336';
  };

  // Chart data
  const ecosystemData = [
    { name: 'npm', value: packages.filter(p => p.ecosystem === 'npm').length, color: '#cb3837' },
    { name: 'PyPI', value: packages.filter(p => p.ecosystem === 'pypi').length, color: '#3776ab' },
    { name: 'Maven', value: 0, color: '#ed8b00' },
    { name: 'NuGet', value: 0, color: '#004880' }
  ];

  const riskData = [
    { name: 'Safe', value: packages.filter(p => p.status === 'safe').length, color: '#4caf50' },
    { name: 'Warning', value: packages.filter(p => p.status === 'warning').length, color: '#ff9800' },
    { name: 'Critical', value: packages.filter(p => p.status === 'critical').length, color: '#f44336' }
  ];

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '400px' }}>
        <LoadingSpinner message="Loading supply chain data..." />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          Supply Chain Management
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => window.location.reload()}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<DownloadIcon />}
          >
            Export Report
          </Button>
        </Box>
      </Box>

      <Tabs value={tabValue} onChange={handleTabChange} sx={{ mb: 3 }}>
        <Tab label="Overview" />
        <Tab label="Package Inventory" />
        <Tab label="Risk Analysis" />
        <Tab label="Compliance" />
      </Tabs>

      <TabPanel value={tabValue} index={0}>
        {/* Overview Tab */}
        <Grid container spacing={3}>
          {/* Summary Cards */}
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <DependencyIcon color="primary" sx={{ mr: 1 }} />
                  <Typography variant="h6">Total Packages</Typography>
                </Box>
                <Typography variant="h3" color="primary">
                  {packages.length}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Across {new Set(packages.map(p => p.ecosystem)).size} ecosystems
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <WarningIcon color="warning" sx={{ mr: 1 }} />
                  <Typography variant="h6">Vulnerabilities</Typography>
                </Box>
                <Typography variant="h3" color="warning.main">
                  {packages.reduce((sum, p) => sum + p.vulnerabilities, 0)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {packages.filter(p => p.vulnerabilities > 0).length} packages affected
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <SpeedIcon color="info" sx={{ mr: 1 }} />
                  <Typography variant="h6">Avg Risk Score</Typography>
                </Box>
                <Typography variant="h3" color="info.main">
                  {(packages.reduce((sum, p) => sum + p.riskScore, 0) / packages.length).toFixed(1)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Out of 10
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <ShieldIcon color="success" sx={{ mr: 1 }} />
                  <Typography variant="h6">Compliance</Typography>
                </Box>
                <Typography variant="h3" color="success.main">
                  {Math.round((packages.filter(p => p.compliance.license && p.compliance.security && p.compliance.maintainer).length / packages.length) * 100)}%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Fully compliant
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          {/* Charts */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Package Distribution by Ecosystem
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={ecosystemData}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {ecosystemData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Risk Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={riskData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="value" fill={(entry) => entry.color} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        {/* Package Inventory Tab */}
        <Box sx={{ mb: 3 }}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                placeholder="Search packages..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon />
                    </InputAdornment>
                  ),
                }}
              />
            </Grid>
            <Grid item xs={12} md={3}>
              <FormControl fullWidth>
                <InputLabel>Ecosystem</InputLabel>
                <Select
                  value={selectedEcosystem}
                  label="Ecosystem"
                  onChange={(e) => setSelectedEcosystem(e.target.value)}
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
                <InputLabel>Risk Level</InputLabel>
                <Select
                  value={selectedRisk}
                  label="Risk Level"
                  onChange={(e) => setSelectedRisk(e.target.value)}
                >
                  <MenuItem value="all">All Risk Levels</MenuItem>
                  <MenuItem value="safe">Safe</MenuItem>
                  <MenuItem value="warning">Warning</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={2}>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<FilterIcon />}
              >
                More Filters
              </Button>
            </Grid>
          </Grid>
        </Box>

        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Package</TableCell>
                <TableCell>Version</TableCell>
                <TableCell>Ecosystem</TableCell>
                <TableCell>Risk Score</TableCell>
                <TableCell>Vulnerabilities</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredPackages.map((pkg) => (
                <TableRow key={pkg.id} hover>
                  <TableCell>
                    <Box>
                      <Typography variant="subtitle2">{pkg.name}</Typography>
                      <Typography variant="body2" color="text.secondary">
                        {pkg.maintainer}
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell>{pkg.version}</TableCell>
                  <TableCell>
                    <Chip label={pkg.ecosystem} size="small" />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <Box sx={{ width: '100%', mr: 1 }}>
                        <LinearProgress
                          variant="determinate"
                          value={(pkg.riskScore / 10) * 100}
                          sx={{
                            backgroundColor: '#e0e0e0',
                            '& .MuiLinearProgress-bar': {
                              backgroundColor: getRiskScoreColor(pkg.riskScore)
                            }
                          }}
                        />
                      </Box>
                      <Typography variant="body2" sx={{ minWidth: 35 }}>
                        {pkg.riskScore}/10
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    {pkg.vulnerabilities > 0 ? (
                      <Chip
                        label={pkg.vulnerabilities}
                        color="error"
                        size="small"
                        icon={<BugIcon />}
                      />
                    ) : (
                      <Chip label="0" color="success" size="small" />
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={pkg.status}
                      color={getStatusColor(pkg.status) as any}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <IconButton
                      size="small"
                      onClick={() => handlePackageClick(pkg)}
                    >
                      <ViewIcon />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        {/* Risk Analysis Tab */}
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Alert severity="info" sx={{ mb: 3 }}>
              Risk analysis helps identify potential security threats and compliance issues in your supply chain.
            </Alert>
          </Grid>

          {/* High Risk Packages */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  High Risk Packages
                </Typography>
                <List>
                  {packages
                    .filter(p => p.riskScore >= 7)
                    .map((pkg) => (
                      <ListItem key={pkg.id}>
                        <ListItemIcon>
                          <WarningIcon color="error" />
                        </ListItemIcon>
                        <ListItemText
                          primary={pkg.name}
                          secondary={`Risk Score: ${pkg.riskScore}/10 • ${pkg.vulnerabilities} vulnerabilities`}
                        />
                      </ListItem>
                    ))}
                </List>
              </CardContent>
            </Card>
          </Grid>

          {/* Compliance Issues */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Compliance Issues
                </Typography>
                <List>
                  {packages
                    .filter(p => !p.compliance.license || !p.compliance.security || !p.compliance.maintainer)
                    .map((pkg) => (
                      <ListItem key={pkg.id}>
                        <ListItemIcon>
                          <SecurityIcon color="warning" />
                        </ListItemIcon>
                        <ListItemText
                          primary={pkg.name}
                          secondary={
                            `Issues: ${!pkg.compliance.license ? 'License ' : ''}${!pkg.compliance.security ? 'Security ' : ''}${!pkg.compliance.maintainer ? 'Maintainer' : ''}`
                          }
                        />
                      </ListItem>
                    ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        {/* Compliance Tab */}
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  License Compliance
                </Typography>
                <Typography variant="h3" color="primary">
                  {Math.round((packages.filter(p => p.compliance.license).length / packages.length) * 100)}%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {packages.filter(p => p.compliance.license).length} of {packages.length} packages
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Security Compliance
                </Typography>
                <Typography variant="h3" color="warning.main">
                  {Math.round((packages.filter(p => p.compliance.security).length / packages.length) * 100)}%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {packages.filter(p => p.compliance.security).length} of {packages.length} packages
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Maintainer Verification
                </Typography>
                <Typography variant="h3" color="success.main">
                  {Math.round((packages.filter(p => p.compliance.maintainer).length / packages.length) * 100)}%
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {packages.filter(p => p.compliance.maintainer).length} of {packages.length} packages
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Package Details Dialog */}
      <Dialog
        open={packageDialogOpen}
        onClose={() => setPackageDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        {selectedPackage && (
          <>
            <DialogTitle>
              {selectedPackage.name} v{selectedPackage.version}
            </DialogTitle>
            <DialogContent>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="body2" color="text.secondary">
                    Ecosystem
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedPackage.ecosystem}
                  </Typography>

                  <Typography variant="body2" color="text.secondary">
                    Maintainer
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedPackage.maintainer}
                  </Typography>

                  <Typography variant="body2" color="text.secondary">
                    Last Updated
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedPackage.lastUpdated.toLocaleDateString()}
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="body2" color="text.secondary">
                    Risk Score
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedPackage.riskScore}/10
                  </Typography>

                  <Typography variant="body2" color="text.secondary">
                    Vulnerabilities
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedPackage.vulnerabilities}
                  </Typography>

                  <Typography variant="body2" color="text.secondary">
                    Dependencies
                  </Typography>
                  <Typography variant="body1" gutterBottom>
                    {selectedPackage.dependencies}
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Licenses
                  </Typography>
                  {selectedPackage.licenses.map(license => (
                    <Chip key={license} label={license} size="small" sx={{ mr: 0.5 }} />
                  ))}
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setPackageDialogOpen(false)}>Close</Button>
              <Button variant="outlined">View Dependencies</Button>
              <Button variant="contained">Generate Report</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
};

export default SupplyChainView;
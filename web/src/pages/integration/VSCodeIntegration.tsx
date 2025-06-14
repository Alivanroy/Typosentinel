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
  Switch,
  FormControlLabel,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Badge,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Code as CodeIcon,
  Extension as ExtensionIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Settings as SettingsIcon,
  History as HistoryIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Info as InfoIcon,
  FileCopy as CopyIcon,
  GetApp as InstallIcon,
  CloudUpload as CloudUploadIcon,
  Schedule as ScheduleIcon,
  Notifications as NotificationsIcon,
  Build as BuildIcon,
  Storage as StorageIcon,
  Speed as SpeedIcon,
  Visibility as ViewIcon,
  Edit as EditIcon,
  FolderOpen as FolderIcon,
  Description as FileIcon,
  BugReport as BugIcon,
  Lightbulb as LightbulbIcon,
  AutoFixHigh as AutoFixIcon,
  Timeline as TimelineIcon,
  Dashboard as DashboardIcon,
  TrendingUp as TrendingUpIcon,
} from '@mui/icons-material';
import { useSocket } from '../../contexts/SocketContext';

interface VSCodeWorkspace {
  id: string;
  name: string;
  path: string;
  language: string;
  packageManager: 'npm' | 'yarn' | 'pnpm' | 'pip' | 'maven' | 'gradle';
  lastScan?: Date;
  status: 'connected' | 'disconnected' | 'scanning' | 'error';
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  files: {
    total: number;
    scanned: number;
    withIssues: number;
  };
}

interface VSCodeScan {
  id: string;
  workspaceId: string;
  workspaceName: string;
  trigger: 'manual' | 'auto' | 'save' | 'install';
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  startTime: Date;
  endTime?: Date;
  progress: number;
  currentFile?: string;
  results?: {
    filesScanned: number;
    packagesAnalyzed: number;
    vulnerabilitiesFound: number;
    riskScore: number;
    findings: VSCodeFinding[];
  };
}

interface VSCodeFinding {
  id: string;
  type: 'typosquatting' | 'malicious' | 'suspicious' | 'outdated' | 'license';
  severity: 'critical' | 'high' | 'medium' | 'low';
  file: string;
  line: number;
  column: number;
  package: string;
  message: string;
  suggestion?: string;
  autoFixAvailable: boolean;
}

interface ExtensionSettings {
  autoScanOnSave: boolean;
  autoScanOnInstall: boolean;
  realTimeAnalysis: boolean;
  showInlineWarnings: boolean;
  notificationLevel: 'all' | 'high' | 'critical' | 'none';
  excludePatterns: string[];
  includeDevDependencies: boolean;
  maxConcurrentScans: number;
  scanTimeout: number;
  apiEndpoint: string;
  apiKey: string;
}

const VSCodeIntegration: React.FC = () => {
  const [workspaces, setWorkspaces] = useState<VSCodeWorkspace[]>([]);
  const [scans, setScans] = useState<VSCodeScan[]>([]);
  const [findings, setFindings] = useState<VSCodeFinding[]>([]);
  const [settings, setSettings] = useState<ExtensionSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTab, setSelectedTab] = useState(0);
  const [settingsDialogOpen, setSettingsDialogOpen] = useState(false);
  const [installDialogOpen, setInstallDialogOpen] = useState(false);
  const [findingDialogOpen, setFindingDialogOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<VSCodeFinding | null>(null);
  const [activeStep, setActiveStep] = useState(0);
  const { scanEvents } = useSocket();

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    // Listen for real-time scan events from VSCode extension
    if (scanEvents.length > 0) {
      const latestEvent = scanEvents[scanEvents.length - 1];
      if (latestEvent.source === 'vscode') {
        updateScanFromEvent(latestEvent);
      }
    }
  }, [scanEvents]);

  const loadData = async () => {
    try {
      // Mock VSCode workspaces
      const mockWorkspaces: VSCodeWorkspace[] = [
        {
          id: '1',
          name: 'typosentinel-web',
          path: '/Users/dev/projects/typosentinel/web',
          language: 'TypeScript',
          packageManager: 'npm',
          lastScan: new Date('2025-06-14T10:30:00'),
          status: 'connected',
          findings: { critical: 1, high: 2, medium: 5, low: 8 },
          files: { total: 156, scanned: 156, withIssues: 12 },
        },
        {
          id: '2',
          name: 'api-gateway',
          path: '/Users/dev/projects/api-gateway',
          language: 'JavaScript',
          packageManager: 'yarn',
          lastScan: new Date('2025-06-14T09:15:00'),
          status: 'connected',
          findings: { critical: 0, high: 1, medium: 3, low: 4 },
          files: { total: 89, scanned: 89, withIssues: 6 },
        },
        {
          id: '3',
          name: 'ml-pipeline',
          path: '/Users/dev/projects/ml-pipeline',
          language: 'Python',
          packageManager: 'pip',
          lastScan: new Date('2025-06-14T08:45:00'),
          status: 'scanning',
          findings: { critical: 2, high: 3, medium: 1, low: 2 },
          files: { total: 67, scanned: 45, withIssues: 8 },
        },
      ];

      // Mock VSCode scans
      const mockScans: VSCodeScan[] = [
        {
          id: '1',
          workspaceId: '1',
          workspaceName: 'typosentinel-web',
          trigger: 'manual',
          status: 'completed',
          startTime: new Date('2025-06-14T10:30:00'),
          endTime: new Date('2025-06-14T10:32:15'),
          progress: 100,
          results: {
            filesScanned: 156,
            packagesAnalyzed: 245,
            vulnerabilitiesFound: 16,
            riskScore: 6.2,
            findings: [],
          },
        },
        {
          id: '2',
          workspaceId: '3',
          workspaceName: 'ml-pipeline',
          trigger: 'auto',
          status: 'running',
          startTime: new Date('2025-06-14T11:00:00'),
          progress: 67,
          currentFile: 'requirements.txt',
        },
      ];

      // Mock findings
      const mockFindings: VSCodeFinding[] = [
        {
          id: '1',
          type: 'typosquatting',
          severity: 'critical',
          file: 'package.json',
          line: 15,
          column: 8,
          package: 'recat',
          message: 'Potential typosquatting: "recat" is similar to "react"',
          suggestion: 'Did you mean "react"?',
          autoFixAvailable: true,
        },
        {
          id: '2',
          type: 'malicious',
          severity: 'critical',
          file: 'package.json',
          line: 23,
          column: 8,
          package: 'suspicious-package',
          message: 'Package contains malicious code that attempts to access environment variables',
          suggestion: 'Remove this package immediately',
          autoFixAvailable: false,
        },
        {
          id: '3',
          type: 'suspicious',
          severity: 'high',
          file: 'package.json',
          line: 18,
          column: 8,
          package: 'lodash-utils',
          message: 'Package has suspicious characteristics: new maintainer, low download count',
          suggestion: 'Consider using the official "lodash" package instead',
          autoFixAvailable: false,
        },
        {
          id: '4',
          type: 'outdated',
          severity: 'medium',
          file: 'package.json',
          line: 20,
          column: 8,
          package: 'express',
          message: 'Package version is outdated and contains known vulnerabilities',
          suggestion: 'Update to version 4.18.2 or later',
          autoFixAvailable: true,
        },
      ];

      // Mock extension settings
      const mockSettings: ExtensionSettings = {
        autoScanOnSave: true,
        autoScanOnInstall: true,
        realTimeAnalysis: true,
        showInlineWarnings: true,
        notificationLevel: 'high',
        excludePatterns: ['node_modules/**', '*.test.js', 'dist/**'],
        includeDevDependencies: false,
        maxConcurrentScans: 3,
        scanTimeout: 300,
        apiEndpoint: 'https://api.typosentinel.com',
        apiKey: 'ts_****************************',
      };

      setWorkspaces(mockWorkspaces);
      setScans(mockScans);
      setFindings(mockFindings);
      setSettings(mockSettings);
    } catch (error) {
      console.error('Failed to load VSCode data:', error);
    } finally {
      setLoading(false);
    }
  };

  const updateScanFromEvent = (event: any) => {
    setScans(prev => {
      const scanIndex = prev.findIndex(s => s.id === event.scanId);
      if (scanIndex >= 0) {
        const updatedScans = [...prev];
        const scan = updatedScans[scanIndex];
        
        switch (event.type) {
          case 'scan:progress':
            scan.progress = event.progress;
            scan.currentFile = event.currentFile;
            break;
          case 'scan:completed':
            scan.status = 'completed';
            scan.endTime = new Date();
            scan.progress = 100;
            scan.results = event.results;
            break;
          case 'scan:error':
            scan.status = 'failed';
            scan.endTime = new Date();
            break;
        }
        
        return updatedScans;
      }
      return prev;
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected': return 'success';
      case 'scanning': return 'info';
      case 'disconnected': return 'warning';
      case 'error': return 'error';
      default: return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected': return <CheckCircleIcon />;
      case 'scanning': return <PlayIcon />;
      case 'disconnected': return <WarningIcon />;
      case 'error': return <ErrorIcon />;
      default: return <InfoIcon />;
    }
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

  const getFindingIcon = (type: string) => {
    switch (type) {
      case 'typosquatting': return <EditIcon />;
      case 'malicious': return <BugIcon />;
      case 'suspicious': return <WarningIcon />;
      case 'outdated': return <TimelineIcon />;
      case 'license': return <SecurityIcon />;
      default: return <InfoIcon />;
    }
  };

  const installationSteps = [
    {
      label: 'Install Extension',
      content: 'Install the TypoSentinel extension from the VS Code Marketplace.',
    },
    {
      label: 'Configure API Key',
      content: 'Set up your API key in the extension settings.',
    },
    {
      label: 'Configure Workspace',
      content: 'Configure scan settings for your workspace.',
    },
    {
      label: 'Start Scanning',
      content: 'Run your first scan to detect potential security issues.',
    },
  ];

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          VS Code Integration
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button 
            variant="outlined" 
            startIcon={<InstallIcon />}
            onClick={() => setInstallDialogOpen(true)}
          >
            Installation Guide
          </Button>
          <Button 
            variant="outlined" 
            startIcon={<SettingsIcon />}
            onClick={() => setSettingsDialogOpen(true)}
          >
            Extension Settings
          </Button>
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={loadData}>
            Refresh
          </Button>
        </Box>
      </Box>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={selectedTab} onChange={(_, newValue) => setSelectedTab(newValue)}>
          <Tab label="Workspaces" />
          <Tab label="Active Scans" />
          <Tab label="Findings" />
          <Tab label="Analytics" />
        </Tabs>
      </Box>

      {/* Workspaces Tab */}
      {selectedTab === 0 && (
        <Grid container spacing={3}>
          {workspaces.map((workspace) => (
            <Grid item xs={12} md={6} lg={4} key={workspace.id}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <FolderIcon sx={{ mr: 1, color: 'primary.main' }} />
                      <Box>
                        <Typography variant="h6">
                          {workspace.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {workspace.language} • {workspace.packageManager}
                        </Typography>
                      </Box>
                    </Box>
                    <Chip 
                      label={workspace.status} 
                      color={getStatusColor(workspace.status) as any}
                      size="small"
                      icon={getStatusIcon(workspace.status)}
                    />
                  </Box>

                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {workspace.path}
                  </Typography>

                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Files Scanned
                      </Typography>
                      <Typography variant="h6">
                        {workspace.files.scanned}/{workspace.files.total}
                      </Typography>
                    </Box>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        Issues Found
                      </Typography>
                      <Typography variant="h6">
                        {workspace.files.withIssues}
                      </Typography>
                    </Box>
                  </Box>

                  <Box sx={{ display: 'flex', gap: 0.5, mb: 2 }}>
                    {workspace.findings.critical > 0 && (
                      <Chip 
                        label={`${workspace.findings.critical}C`} 
                        size="small"
                        sx={{ backgroundColor: '#d32f2f', color: 'white', fontSize: '0.7rem' }}
                      />
                    )}
                    {workspace.findings.high > 0 && (
                      <Chip 
                        label={`${workspace.findings.high}H`} 
                        size="small"
                        sx={{ backgroundColor: '#f57c00', color: 'white', fontSize: '0.7rem' }}
                      />
                    )}
                    {workspace.findings.medium > 0 && (
                      <Chip 
                        label={`${workspace.findings.medium}M`} 
                        size="small"
                        sx={{ backgroundColor: '#1976d2', color: 'white', fontSize: '0.7rem' }}
                      />
                    )}
                    {workspace.findings.low > 0 && (
                      <Chip 
                        label={`${workspace.findings.low}L`} 
                        size="small"
                        sx={{ backgroundColor: '#388e3c', color: 'white', fontSize: '0.7rem' }}
                      />
                    )}
                  </Box>

                  {workspace.lastScan && (
                    <Typography variant="caption" color="text.secondary">
                      Last scan: {workspace.lastScan.toLocaleString()}
                    </Typography>
                  )}

                  <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                    <Button size="small" variant="outlined" disabled={workspace.status === 'scanning'}>
                      {workspace.status === 'scanning' ? 'Scanning...' : 'Scan Now'}
                    </Button>
                    <Button size="small" variant="outlined">
                      View Details
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Active Scans Tab */}
      {selectedTab === 1 && (
        <Grid container spacing={3}>
          {scans
            .filter(scan => scan.status === 'running')
            .map((scan) => (
              <Grid item xs={12} key={scan.id}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                      <Box>
                        <Typography variant="h6">
                          {scan.workspaceName}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Triggered by: {scan.trigger} • Started: {scan.startTime.toLocaleTimeString()}
                        </Typography>
                      </Box>
                      <Chip 
                        label={scan.status} 
                        color="info"
                        icon={<PlayIcon />}
                      />
                    </Box>
                    
                    <Box sx={{ mb: 2 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                        <Typography variant="body2">Progress</Typography>
                        <Typography variant="body2">{scan.progress}%</Typography>
                      </Box>
                      <LinearProgress variant="determinate" value={scan.progress} />
                    </Box>

                    {scan.currentFile && (
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        Currently scanning: {scan.currentFile}
                      </Typography>
                    )}

                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Button size="small" variant="outlined" color="error">
                        Cancel Scan
                      </Button>
                      <Button size="small" variant="outlined">
                        View Live Results
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          
          {scans.filter(scan => scan.status === 'running').length === 0 && (
            <Grid item xs={12}>
              <Card>
                <CardContent sx={{ textAlign: 'center', py: 4 }}>
                  <ExtensionIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary">
                    No Active Scans
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Start a scan from VS Code to see active scans here.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      )}

      {/* Findings Tab */}
      {selectedTab === 2 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Security Findings
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>File</TableCell>
                    <TableCell>Package</TableCell>
                    <TableCell>Message</TableCell>
                    <TableCell>Auto Fix</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {findings.map((finding) => (
                    <TableRow key={finding.id} hover>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          {getFindingIcon(finding.type)}
                          <Typography variant="body2" sx={{ ml: 1, textTransform: 'capitalize' }}>
                            {finding.type}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={finding.severity.toUpperCase()} 
                          sx={{ 
                            backgroundColor: getSeverityColor(finding.severity),
                            color: 'white'
                          }}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Box>
                          <Typography variant="body2" fontWeight={500}>
                            {finding.file}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            Line {finding.line}, Column {finding.column}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {finding.package}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {finding.message}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {finding.autoFixAvailable ? (
                          <Chip 
                            label="Available" 
                            color="success"
                            size="small"
                            icon={<AutoFixIcon />}
                          />
                        ) : (
                          <Chip 
                            label="Manual" 
                            color="default"
                            size="small"
                          />
                        )}
                      </TableCell>
                      <TableCell>
                        <Button 
                          size="small" 
                          variant="outlined"
                          onClick={() => {
                            setSelectedFinding(finding);
                            setFindingDialogOpen(true);
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
      )}

      {/* Analytics Tab */}
      {selectedTab === 3 && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom>
                      Connected Workspaces
                    </Typography>
                    <Typography variant="h4">
                      {workspaces.filter(w => w.status === 'connected').length}
                    </Typography>
                  </Box>
                  <FolderIcon sx={{ fontSize: 40, color: 'primary.main' }} />
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
                      Total Findings
                    </Typography>
                    <Typography variant="h4">
                      {findings.length}
                    </Typography>
                  </Box>
                  <BugIcon sx={{ fontSize: 40, color: 'warning.main' }} />
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
                      Critical Issues
                    </Typography>
                    <Typography variant="h4" color="error.main">
                      {findings.filter(f => f.severity === 'critical').length}
                    </Typography>
                  </Box>
                  <ErrorIcon sx={{ fontSize: 40, color: 'error.main' }} />
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
                      Auto-Fixable
                    </Typography>
                    <Typography variant="h4" color="success.main">
                      {findings.filter(f => f.autoFixAvailable).length}
                    </Typography>
                  </Box>
                  <AutoFixIcon sx={{ fontSize: 40, color: 'success.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Finding Details Dialog */}
      <Dialog 
        open={findingDialogOpen} 
        onClose={() => setFindingDialogOpen(false)} 
        maxWidth="md" 
        fullWidth
      >
        {selectedFinding && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {getFindingIcon(selectedFinding.type)}
                {selectedFinding.type.charAt(0).toUpperCase() + selectedFinding.type.slice(1)} Issue
                <Chip 
                  label={selectedFinding.severity.toUpperCase()} 
                  sx={{ 
                    backgroundColor: getSeverityColor(selectedFinding.severity),
                    color: 'white'
                  }}
                  size="small"
                />
              </Box>
            </DialogTitle>
            <DialogContent>
              <Grid container spacing={2} sx={{ mb: 2 }}>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    File
                  </Typography>
                  <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                    {selectedFinding.file}:{selectedFinding.line}:{selectedFinding.column}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" color="text.secondary">
                    Package
                  </Typography>
                  <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                    {selectedFinding.package}
                  </Typography>
                </Grid>
              </Grid>

              <Typography variant="body2" color="text.secondary">
                Issue Description
              </Typography>
              <Typography variant="body1" sx={{ mb: 2 }}>
                {selectedFinding.message}
              </Typography>

              {selectedFinding.suggestion && (
                <>
                  <Typography variant="body2" color="text.secondary">
                    Suggested Action
                  </Typography>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    {selectedFinding.suggestion}
                  </Alert>
                </>
              )}

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  Auto Fix Available:
                </Typography>
                {selectedFinding.autoFixAvailable ? (
                  <Chip 
                    label="Yes" 
                    color="success"
                    size="small"
                    icon={<AutoFixIcon />}
                  />
                ) : (
                  <Chip 
                    label="No" 
                    color="default"
                    size="small"
                  />
                )}
              </Box>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setFindingDialogOpen(false)}>Close</Button>
              {selectedFinding.autoFixAvailable && (
                <Button variant="contained" startIcon={<AutoFixIcon />}>
                  Apply Auto Fix
                </Button>
              )}
              <Button variant="outlined">
                Open in VS Code
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Extension Settings Dialog */}
      <Dialog 
        open={settingsDialogOpen} 
        onClose={() => setSettingsDialogOpen(false)} 
        maxWidth="md" 
        fullWidth
      >
        <DialogTitle>VS Code Extension Settings</DialogTitle>
        <DialogContent>
          {settings && (
            <Grid container spacing={3} sx={{ mt: 1 }}>
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Scan Settings
                </Typography>
              </Grid>
              <Grid item xs={6}>
                <FormControlLabel
                  control={
                    <Switch 
                      checked={settings.autoScanOnSave}
                      onChange={(e) => setSettings({...settings, autoScanOnSave: e.target.checked})}
                    />
                  }
                  label="Auto Scan on Save"
                />
              </Grid>
              <Grid item xs={6}>
                <FormControlLabel
                  control={
                    <Switch 
                      checked={settings.autoScanOnInstall}
                      onChange={(e) => setSettings({...settings, autoScanOnInstall: e.target.checked})}
                    />
                  }
                  label="Auto Scan on Package Install"
                />
              </Grid>
              <Grid item xs={6}>
                <FormControlLabel
                  control={
                    <Switch 
                      checked={settings.realTimeAnalysis}
                      onChange={(e) => setSettings({...settings, realTimeAnalysis: e.target.checked})}
                    />
                  }
                  label="Real-time Analysis"
                />
              </Grid>
              <Grid item xs={6}>
                <FormControlLabel
                  control={
                    <Switch 
                      checked={settings.showInlineWarnings}
                      onChange={(e) => setSettings({...settings, showInlineWarnings: e.target.checked})}
                    />
                  }
                  label="Show Inline Warnings"
                />
              </Grid>
              
              <Grid item xs={12}>
                <Divider sx={{ my: 2 }} />
                <Typography variant="h6" gutterBottom>
                  API Configuration
                </Typography>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="API Endpoint"
                  value={settings.apiEndpoint}
                  onChange={(e) => setSettings({...settings, apiEndpoint: e.target.value})}
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="API Key"
                  type="password"
                  value={settings.apiKey}
                  onChange={(e) => setSettings({...settings, apiKey: e.target.value})}
                />
              </Grid>
              
              <Grid item xs={12}>
                <Divider sx={{ my: 2 }} />
                <Typography variant="h6" gutterBottom>
                  Notification Settings
                </Typography>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Notification Level</InputLabel>
                  <Select
                    value={settings.notificationLevel}
                    label="Notification Level"
                    onChange={(e) => setSettings({...settings, notificationLevel: e.target.value as any})}
                  >
                    <MenuItem value="all">All Issues</MenuItem>
                    <MenuItem value="high">High & Critical</MenuItem>
                    <MenuItem value="critical">Critical Only</MenuItem>
                    <MenuItem value="none">None</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControlLabel
                  control={
                    <Switch 
                      checked={settings.includeDevDependencies}
                      onChange={(e) => setSettings({...settings, includeDevDependencies: e.target.checked})}
                    />
                  }
                  label="Include Dev Dependencies"
                />
              </Grid>
              
              <Grid item xs={12}>
                <Divider sx={{ my: 2 }} />
                <Typography variant="h6" gutterBottom>
                  Performance Settings
                </Typography>
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Max Concurrent Scans"
                  type="number"
                  value={settings.maxConcurrentScans}
                  onChange={(e) => setSettings({...settings, maxConcurrentScans: parseInt(e.target.value)})}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Scan Timeout (seconds)"
                  type="number"
                  value={settings.scanTimeout}
                  onChange={(e) => setSettings({...settings, scanTimeout: parseInt(e.target.value)})}
                />
              </Grid>
              
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Exclude Patterns (comma-separated)"
                  value={settings.excludePatterns.join(', ')}
                  onChange={(e) => setSettings({...settings, excludePatterns: e.target.value.split(', ').filter(p => p.trim())})}
                  helperText="Patterns to exclude from scanning (e.g., node_modules/**, *.test.js)"
                />
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSettingsDialogOpen(false)}>Cancel</Button>
          <Button variant="contained">Save Settings</Button>
        </DialogActions>
      </Dialog>

      {/* Installation Guide Dialog */}
      <Dialog 
        open={installDialogOpen} 
        onClose={() => setInstallDialogOpen(false)} 
        maxWidth="md" 
        fullWidth
      >
        <DialogTitle>VS Code Extension Installation Guide</DialogTitle>
        <DialogContent>
          <Stepper activeStep={activeStep} orientation="vertical">
            {installationSteps.map((step, index) => (
              <Step key={step.label}>
                <StepLabel>{step.label}</StepLabel>
                <StepContent>
                  <Typography>{step.content}</Typography>
                  {index === 0 && (
                    <Box sx={{ mt: 2, p: 2, backgroundColor: 'grey.100', borderRadius: 1 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Installation Methods:
                      </Typography>
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="body2" gutterBottom>
                          1. From VS Code Marketplace:
                        </Typography>
                        <Box sx={{ fontFamily: 'monospace', backgroundColor: 'white', p: 1, borderRadius: 1 }}>
                          Ctrl+Shift+X → Search "TypoSentinel" → Install
                        </Box>
                      </Box>
                      <Box>
                        <Typography variant="body2" gutterBottom>
                          2. From Command Line:
                        </Typography>
                        <Box sx={{ fontFamily: 'monospace', backgroundColor: 'white', p: 1, borderRadius: 1 }}>
                          code --install-extension typosentinel.typosentinel-vscode
                        </Box>
                      </Box>
                    </Box>
                  )}
                  {index === 1 && (
                    <Box sx={{ mt: 2, p: 2, backgroundColor: 'grey.100', borderRadius: 1 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Configuration Steps:
                      </Typography>
                      <Box sx={{ fontFamily: 'monospace', backgroundColor: 'white', p: 1, borderRadius: 1 }}>
                        1. Open VS Code Settings (Ctrl+,)<br/>
                        2. Search for "TypoSentinel"<br/>
                        3. Set API Key: ts_your_api_key_here<br/>
                        4. Set API Endpoint: https://api.typosentinel.com
                      </Box>
                    </Box>
                  )}
                  {index === 2 && (
                    <Box sx={{ mt: 2, p: 2, backgroundColor: 'grey.100', borderRadius: 1 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Workspace Configuration:
                      </Typography>
                      <Box sx={{ fontFamily: 'monospace', backgroundColor: 'white', p: 1, borderRadius: 1 }}>
                        1. Open your project in VS Code<br/>
                        2. Create .vscode/settings.json<br/>
                        3. Configure scan settings<br/>
                        4. Set exclude patterns if needed
                      </Box>
                    </Box>
                  )}
                  {index === 3 && (
                    <Box sx={{ mt: 2, p: 2, backgroundColor: 'grey.100', borderRadius: 1 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Start Your First Scan:
                      </Typography>
                      <Box sx={{ fontFamily: 'monospace', backgroundColor: 'white', p: 1, borderRadius: 1 }}>
                        1. Open Command Palette (Ctrl+Shift+P)<br/>
                        2. Type "TypoSentinel: Scan Workspace"<br/>
                        3. Press Enter to start scanning<br/>
                        4. View results in Problems panel
                      </Box>
                    </Box>
                  )}
                  <Box sx={{ mb: 1, mt: 2 }}>
                    <Button
                      variant="contained"
                      onClick={() => setActiveStep(index + 1)}
                      sx={{ mt: 1, mr: 1 }}
                      disabled={index === installationSteps.length - 1}
                    >
                      {index === installationSteps.length - 1 ? 'Finish' : 'Continue'}
                    </Button>
                    <Button
                      disabled={index === 0}
                      onClick={() => setActiveStep(index - 1)}
                      sx={{ mt: 1, mr: 1 }}
                    >
                      Back
                    </Button>
                  </Box>
                </StepContent>
              </Step>
            ))}
          </Stepper>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setInstallDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default VSCodeIntegration;
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
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Terminal as TerminalIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Settings as SettingsIcon,
  History as HistoryIcon,
  Code as CodeIcon,
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
} from '@mui/icons-material';
import { useSocket } from '../../contexts/SocketContext';

interface CLICommand {
  id: string;
  command: string;
  description: string;
  example: string;
  category: 'scan' | 'config' | 'server' | 'batch' | 'policy';
  parameters: {
    name: string;
    type: 'string' | 'boolean' | 'number' | 'array';
    required: boolean;
    description: string;
    default?: any;
  }[];
}

interface ScanSession {
  id: string;
  command: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  startTime: Date;
  endTime?: Date;
  progress: number;
  results?: {
    packagesScanned: number;
    vulnerabilitiesFound: number;
    riskScore: number;
    findings: any[];
  };
  logs: string[];
}

interface CLIConfig {
  apiEndpoint: string;
  apiKey: string;
  outputFormat: 'json' | 'table' | 'csv';
  verbosity: 'quiet' | 'normal' | 'verbose' | 'debug';
  autoUpdate: boolean;
  notifications: boolean;
  maxConcurrency: number;
  timeout: number;
  cacheEnabled: boolean;
  reportPath: string;
}

const CLIIntegration: React.FC = () => {
  const [commands, setCommands] = useState<CLICommand[]>([]);
  const [sessions, setSessions] = useState<ScanSession[]>([]);
  const [config, setConfig] = useState<CLIConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTab, setSelectedTab] = useState(0);
  const [commandDialogOpen, setCommandDialogOpen] = useState(false);
  const [selectedCommand, setSelectedCommand] = useState<CLICommand | null>(null);
  const [configDialogOpen, setConfigDialogOpen] = useState(false);
  const [installDialogOpen, setInstallDialogOpen] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const { scanEvents } = useSocket();

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    // Listen for real-time scan events
    if (scanEvents.length > 0) {
      const latestEvent = scanEvents[scanEvents.length - 1];
      updateSessionFromEvent(latestEvent);
    }
  }, [scanEvents]);

  const loadData = async () => {
    try {
      // Mock CLI commands
      const mockCommands: CLICommand[] = [
        {
          id: '1',
          command: 'typosentinel scan',
          description: 'Scan a package or directory for typosquatting vulnerabilities',
          example: 'typosentinel scan ./package.json',
          category: 'scan',
          parameters: [
            {
              name: 'path',
              type: 'string',
              required: true,
              description: 'Path to package.json or directory to scan',
            },
            {
              name: '--format',
              type: 'string',
              required: false,
              description: 'Output format (json, table, csv)',
              default: 'table',
            },
            {
              name: '--output',
              type: 'string',
              required: false,
              description: 'Output file path',
            },
            {
              name: '--verbose',
              type: 'boolean',
              required: false,
              description: 'Enable verbose logging',
              default: false,
            },
          ],
        },
        {
          id: '2',
          command: 'typosentinel batch',
          description: 'Scan multiple projects in batch mode',
          example: 'typosentinel batch --config batch-config.yaml',
          category: 'batch',
          parameters: [
            {
              name: '--config',
              type: 'string',
              required: true,
              description: 'Path to batch configuration file',
            },
            {
              name: '--parallel',
              type: 'number',
              required: false,
              description: 'Number of parallel scans',
              default: 4,
            },
          ],
        },
        {
          id: '3',
          command: 'typosentinel server',
          description: 'Start the TypoSentinel API server',
          example: 'typosentinel server --port 8080',
          category: 'server',
          parameters: [
            {
              name: '--port',
              type: 'number',
              required: false,
              description: 'Server port',
              default: 8080,
            },
            {
              name: '--host',
              type: 'string',
              required: false,
              description: 'Server host',
              default: 'localhost',
            },
          ],
        },
        {
          id: '4',
          command: 'typosentinel config',
          description: 'Manage CLI configuration',
          example: 'typosentinel config set api-key YOUR_API_KEY',
          category: 'config',
          parameters: [
            {
              name: 'action',
              type: 'string',
              required: true,
              description: 'Action to perform (get, set, list, reset)',
            },
            {
              name: 'key',
              type: 'string',
              required: false,
              description: 'Configuration key',
            },
            {
              name: 'value',
              type: 'string',
              required: false,
              description: 'Configuration value',
            },
          ],
        },
        {
          id: '5',
          command: 'typosentinel policy',
          description: 'Manage security policies',
          example: 'typosentinel policy apply --file security-policy.rego',
          category: 'policy',
          parameters: [
            {
              name: 'action',
              type: 'string',
              required: true,
              description: 'Action to perform (apply, validate, list, remove)',
            },
            {
              name: '--file',
              type: 'string',
              required: false,
              description: 'Policy file path',
            },
            {
              name: '--name',
              type: 'string',
              required: false,
              description: 'Policy name',
            },
          ],
        },
      ];

      // Mock scan sessions
      const mockSessions: ScanSession[] = [
        {
          id: '1',
          command: 'typosentinel scan ./web/package.json',
          status: 'completed',
          startTime: new Date('2025-06-14T10:30:00'),
          endTime: new Date('2025-06-14T10:32:15'),
          progress: 100,
          results: {
            packagesScanned: 245,
            vulnerabilitiesFound: 3,
            riskScore: 6.2,
            findings: [],
          },
          logs: [
            '[10:30:00] Starting scan of ./web/package.json',
            '[10:30:01] Loading package dependencies...',
            '[10:30:05] Analyzing 245 packages',
            '[10:31:20] Found 3 potential vulnerabilities',
            '[10:32:15] Scan completed successfully',
          ],
        },
        {
          id: '2',
          command: 'typosentinel batch --config projects.yaml',
          status: 'running',
          startTime: new Date('2025-06-14T11:00:00'),
          progress: 65,
          logs: [
            '[11:00:00] Starting batch scan',
            '[11:00:01] Loading configuration from projects.yaml',
            '[11:00:02] Found 8 projects to scan',
            '[11:05:30] Completed project 1/8: web-frontend',
            '[11:12:45] Completed project 2/8: api-gateway',
            '[11:18:20] Completed project 3/8: ml-pipeline',
            '[11:25:10] Completed project 4/8: auth-service',
            '[11:32:05] Completed project 5/8: notification-service',
            '[11:35:15] Currently scanning project 6/8: data-processor',
          ],
        },
      ];

      // Mock CLI config
      const mockConfig: CLIConfig = {
        apiEndpoint: 'https://api.typosentinel.com',
        apiKey: 'ts_****************************',
        outputFormat: 'json',
        verbosity: 'normal',
        autoUpdate: true,
        notifications: true,
        maxConcurrency: 4,
        timeout: 300,
        cacheEnabled: true,
        reportPath: './typosentinel-reports',
      };

      setCommands(mockCommands);
      setSessions(mockSessions);
      setConfig(mockConfig);
    } catch (error) {
      console.error('Failed to load CLI data:', error);
    } finally {
      setLoading(false);
    }
  };

  const updateSessionFromEvent = (event: any) => {
    setSessions(prev => {
      const sessionIndex = prev.findIndex(s => s.id === event.sessionId);
      if (sessionIndex >= 0) {
        const updatedSessions = [...prev];
        const session = updatedSessions[sessionIndex];
        
        switch (event.type) {
          case 'scan:progress':
            session.progress = event.progress;
            session.logs.push(`[${new Date().toLocaleTimeString()}] ${event.message}`);
            break;
          case 'scan:completed':
            session.status = 'completed';
            session.endTime = new Date();
            session.progress = 100;
            session.results = event.results;
            session.logs.push(`[${new Date().toLocaleTimeString()}] Scan completed`);
            break;
          case 'scan:error':
            session.status = 'failed';
            session.endTime = new Date();
            session.logs.push(`[${new Date().toLocaleTimeString()}] Error: ${event.error}`);
            break;
        }
        
        return updatedSessions;
      }
      return prev;
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'success';
      case 'running': return 'info';
      case 'failed': return 'error';
      case 'cancelled': return 'warning';
      default: return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircleIcon />;
      case 'running': return <PlayIcon />;
      case 'failed': return <ErrorIcon />;
      case 'cancelled': return <StopIcon />;
      default: return <InfoIcon />;
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'scan': return <SecurityIcon />;
      case 'config': return <SettingsIcon />;
      case 'server': return <StorageIcon />;
      case 'batch': return <BuildIcon />;
      case 'policy': return <CodeIcon />;
      default: return <TerminalIcon />;
    }
  };

  const installationSteps = [
    {
      label: 'Download CLI',
      content: 'Download the latest TypoSentinel CLI binary for your operating system.',
    },
    {
      label: 'Install Binary',
      content: 'Move the binary to your PATH or install using a package manager.',
    },
    {
      label: 'Configure API Key',
      content: 'Set up your API key to connect to the TypoSentinel service.',
    },
    {
      label: 'Verify Installation',
      content: 'Run a test scan to verify the installation is working correctly.',
    },
  ];

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          CLI Integration
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
            onClick={() => setConfigDialogOpen(true)}
          >
            Configuration
          </Button>
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={loadData}>
            Refresh
          </Button>
        </Box>
      </Box>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={selectedTab} onChange={(_, newValue) => setSelectedTab(newValue)}>
          <Tab label="Commands" />
          <Tab label="Active Sessions" />
          <Tab label="History" />
          <Tab label="Monitoring" />
        </Tabs>
      </Box>

      {/* Commands Tab */}
      {selectedTab === 0 && (
        <Grid container spacing={3}>
          {['scan', 'batch', 'server', 'config', 'policy'].map((category) => (
            <Grid item xs={12} key={category}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    {getCategoryIcon(category)}
                    <Typography variant="h6" sx={{ ml: 1, textTransform: 'capitalize' }}>
                      {category} Commands
                    </Typography>
                  </Box>
                  <Grid container spacing={2}>
                    {commands
                      .filter(cmd => cmd.category === category)
                      .map((command) => (
                        <Grid item xs={12} md={6} key={command.id}>
                          <Card variant="outlined">
                            <CardContent>
                              <Typography variant="subtitle1" fontWeight={500}>
                                {command.command}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                {command.description}
                              </Typography>
                              <Box sx={{ 
                                backgroundColor: 'grey.100', 
                                p: 1, 
                                borderRadius: 1, 
                                fontFamily: 'monospace',
                                fontSize: '0.875rem',
                                mb: 1
                              }}>
                                {command.example}
                              </Box>
                              <Button 
                                size="small" 
                                variant="outlined"
                                onClick={() => {
                                  setSelectedCommand(command);
                                  setCommandDialogOpen(true);
                                }}
                              >
                                View Details
                              </Button>
                            </CardContent>
                          </Card>
                        </Grid>
                      ))}
                  </Grid>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Active Sessions Tab */}
      {selectedTab === 1 && (
        <Grid container spacing={3}>
          {sessions
            .filter(session => session.status === 'running')
            .map((session) => (
              <Grid item xs={12} key={session.id}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        {getStatusIcon(session.status)}
                        <Typography variant="h6" sx={{ ml: 1 }}>
                          {session.command}
                        </Typography>
                      </Box>
                      <Chip 
                        label={session.status} 
                        color={getStatusColor(session.status) as any}
                        icon={getStatusIcon(session.status)}
                      />
                    </Box>
                    
                    <Box sx={{ mb: 2 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                        <Typography variant="body2">Progress</Typography>
                        <Typography variant="body2">{session.progress}%</Typography>
                      </Box>
                      <LinearProgress variant="determinate" value={session.progress} />
                    </Box>

                    <Typography variant="subtitle2" gutterBottom>
                      Live Logs
                    </Typography>
                    <Box sx={{ 
                      backgroundColor: 'grey.900', 
                      color: 'white', 
                      p: 2, 
                      borderRadius: 1,
                      fontFamily: 'monospace',
                      fontSize: '0.875rem',
                      maxHeight: 200,
                      overflow: 'auto'
                    }}>
                      {session.logs.map((log, index) => (
                        <div key={index}>{log}</div>
                      ))}
                    </Box>

                    <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                      <Button size="small" variant="outlined" color="error">
                        Cancel
                      </Button>
                      <Button size="small" variant="outlined">
                        View Details
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          
          {sessions.filter(session => session.status === 'running').length === 0 && (
            <Grid item xs={12}>
              <Card>
                <CardContent sx={{ textAlign: 'center', py: 4 }}>
                  <TerminalIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                  <Typography variant="h6" color="text.secondary">
                    No Active Sessions
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Start a scan using the CLI to see active sessions here.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      )}

      {/* History Tab */}
      {selectedTab === 2 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Scan History
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Command</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Start Time</TableCell>
                    <TableCell>Duration</TableCell>
                    <TableCell>Results</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sessions.map((session) => (
                    <TableRow key={session.id} hover>
                      <TableCell>
                        <Box sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                          {session.command}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={session.status} 
                          color={getStatusColor(session.status) as any}
                          size="small"
                          icon={getStatusIcon(session.status)}
                        />
                      </TableCell>
                      <TableCell>
                        {session.startTime.toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {session.endTime ? 
                          `${Math.round((session.endTime.getTime() - session.startTime.getTime()) / 1000)}s` :
                          'Running...'
                        }
                      </TableCell>
                      <TableCell>
                        {session.results ? (
                          <Box>
                            <Typography variant="body2">
                              {session.results.packagesScanned} packages, {session.results.vulnerabilitiesFound} vulnerabilities
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              Risk Score: {session.results.riskScore}
                            </Typography>
                          </Box>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            No results
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Button size="small" variant="outlined">
                          View Report
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

      {/* Monitoring Tab */}
      {selectedTab === 3 && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom>
                      Active Sessions
                    </Typography>
                    <Typography variant="h4">
                      {sessions.filter(s => s.status === 'running').length}
                    </Typography>
                  </Box>
                  <PlayIcon sx={{ fontSize: 40, color: 'primary.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom>
                      Completed Today
                    </Typography>
                    <Typography variant="h4">
                      {sessions.filter(s => s.status === 'completed').length}
                    </Typography>
                  </Box>
                  <CheckCircleIcon sx={{ fontSize: 40, color: 'success.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom>
                      Failed Scans
                    </Typography>
                    <Typography variant="h4">
                      {sessions.filter(s => s.status === 'failed').length}
                    </Typography>
                  </Box>
                  <ErrorIcon sx={{ fontSize: 40, color: 'error.main' }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Command Details Dialog */}
      <Dialog 
        open={commandDialogOpen} 
        onClose={() => setCommandDialogOpen(false)} 
        maxWidth="md" 
        fullWidth
      >
        {selectedCommand && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {getCategoryIcon(selectedCommand.category)}
                {selectedCommand.command}
              </Box>
            </DialogTitle>
            <DialogContent>
              <Typography variant="body1" sx={{ mb: 2 }}>
                {selectedCommand.description}
              </Typography>
              
              <Typography variant="h6" gutterBottom>
                Example Usage
              </Typography>
              <Box sx={{ 
                backgroundColor: 'grey.100', 
                p: 2, 
                borderRadius: 1, 
                fontFamily: 'monospace',
                mb: 2
              }}>
                {selectedCommand.example}
              </Box>

              <Typography variant="h6" gutterBottom>
                Parameters
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Parameter</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Required</TableCell>
                      <TableCell>Description</TableCell>
                      <TableCell>Default</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {selectedCommand.parameters.map((param, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ fontFamily: 'monospace' }}>
                          {param.name}
                        </TableCell>
                        <TableCell>
                          <Chip label={param.type} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={param.required ? 'Yes' : 'No'} 
                            size="small"
                            color={param.required ? 'error' : 'default'}
                          />
                        </TableCell>
                        <TableCell>{param.description}</TableCell>
                        <TableCell sx={{ fontFamily: 'monospace' }}>
                          {param.default !== undefined ? String(param.default) : '-'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setCommandDialogOpen(false)}>Close</Button>
              <Button variant="contained" startIcon={<CopyIcon />}>
                Copy Command
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Configuration Dialog */}
      <Dialog 
        open={configDialogOpen} 
        onClose={() => setConfigDialogOpen(false)} 
        maxWidth="sm" 
        fullWidth
      >
        <DialogTitle>CLI Configuration</DialogTitle>
        <DialogContent>
          {config && (
            <Grid container spacing={2} sx={{ mt: 1 }}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="API Endpoint"
                  value={config.apiEndpoint}
                  onChange={(e) => setConfig({...config, apiEndpoint: e.target.value})}
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="API Key"
                  type="password"
                  value={config.apiKey}
                  onChange={(e) => setConfig({...config, apiKey: e.target.value})}
                />
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Output Format</InputLabel>
                  <Select
                    value={config.outputFormat}
                    label="Output Format"
                    onChange={(e) => setConfig({...config, outputFormat: e.target.value as any})}
                  >
                    <MenuItem value="json">JSON</MenuItem>
                    <MenuItem value="table">Table</MenuItem>
                    <MenuItem value="csv">CSV</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Verbosity</InputLabel>
                  <Select
                    value={config.verbosity}
                    label="Verbosity"
                    onChange={(e) => setConfig({...config, verbosity: e.target.value as any})}
                  >
                    <MenuItem value="quiet">Quiet</MenuItem>
                    <MenuItem value="normal">Normal</MenuItem>
                    <MenuItem value="verbose">Verbose</MenuItem>
                    <MenuItem value="debug">Debug</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Max Concurrency"
                  type="number"
                  value={config.maxConcurrency}
                  onChange={(e) => setConfig({...config, maxConcurrency: parseInt(e.target.value)})}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Timeout (seconds)"
                  type="number"
                  value={config.timeout}
                  onChange={(e) => setConfig({...config, timeout: parseInt(e.target.value)})}
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Report Path"
                  value={config.reportPath}
                  onChange={(e) => setConfig({...config, reportPath: e.target.value})}
                />
              </Grid>
              <Grid item xs={12}>
                <FormControlLabel
                  control={
                    <Switch 
                      checked={config.autoUpdate}
                      onChange={(e) => setConfig({...config, autoUpdate: e.target.checked})}
                    />
                  }
                  label="Auto Update"
                />
              </Grid>
              <Grid item xs={12}>
                <FormControlLabel
                  control={
                    <Switch 
                      checked={config.notifications}
                      onChange={(e) => setConfig({...config, notifications: e.target.checked})}
                    />
                  }
                  label="Enable Notifications"
                />
              </Grid>
              <Grid item xs={12}>
                <FormControlLabel
                  control={
                    <Switch 
                      checked={config.cacheEnabled}
                      onChange={(e) => setConfig({...config, cacheEnabled: e.target.checked})}
                    />
                  }
                  label="Enable Cache"
                />
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigDialogOpen(false)}>Cancel</Button>
          <Button variant="contained">Save Configuration</Button>
        </DialogActions>
      </Dialog>

      {/* Installation Guide Dialog */}
      <Dialog 
        open={installDialogOpen} 
        onClose={() => setInstallDialogOpen(false)} 
        maxWidth="md" 
        fullWidth
      >
        <DialogTitle>TypoSentinel CLI Installation Guide</DialogTitle>
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
                        Download Links:
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        <Button size="small" variant="outlined">macOS (Intel)</Button>
                        <Button size="small" variant="outlined">macOS (Apple Silicon)</Button>
                        <Button size="small" variant="outlined">Linux (x64)</Button>
                        <Button size="small" variant="outlined">Windows (x64)</Button>
                      </Box>
                    </Box>
                  )}
                  {index === 1 && (
                    <Box sx={{ mt: 2, p: 2, backgroundColor: 'grey.100', borderRadius: 1, fontFamily: 'monospace' }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Installation Commands:
                      </Typography>
                      <div># macOS/Linux</div>
                      <div>curl -sSL https://install.typosentinel.com | bash</div>
                      <div></div>
                      <div># Or manually</div>
                      <div>chmod +x typosentinel</div>
                      <div>sudo mv typosentinel /usr/local/bin/</div>
                    </Box>
                  )}
                  {index === 2 && (
                    <Box sx={{ mt: 2, p: 2, backgroundColor: 'grey.100', borderRadius: 1, fontFamily: 'monospace' }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Configuration Commands:
                      </Typography>
                      <div>typosentinel config set api-key YOUR_API_KEY</div>
                      <div>typosentinel config set api-endpoint https://api.typosentinel.com</div>
                    </Box>
                  )}
                  {index === 3 && (
                    <Box sx={{ mt: 2, p: 2, backgroundColor: 'grey.100', borderRadius: 1, fontFamily: 'monospace' }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Test Commands:
                      </Typography>
                      <div>typosentinel --version</div>
                      <div>typosentinel scan --help</div>
                      <div>typosentinel scan ./package.json</div>
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

export default CLIIntegration;
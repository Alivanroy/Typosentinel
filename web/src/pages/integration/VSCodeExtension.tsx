import React, { useState } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  Grid,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Alert,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Tab,
  Tabs,
  Paper,
  Divider,
  IconButton,
  Tooltip
} from '@mui/material';
import {
  Download,
  CheckCircle,
  Settings,
  Code,
  Security,
  PlayArrow,
  Stop,
  Refresh,
  ContentCopy,
  Launch,
  BugReport,
  Extension,
  Terminal,
  Folder,
  FilePresent
} from '@mui/icons-material';

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
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
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

const VSCodeExtension: React.FC = () => {
  const [activeStep, setActiveStep] = useState(0);
  const [tabValue, setTabValue] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [configDialogOpen, setConfigDialogOpen] = useState(false);
  const [apiKey, setApiKey] = useState('');
  const [serverUrl, setServerUrl] = useState('http://localhost:8080');

  const installationSteps = [
    {
      label: 'Install VS Code Extension',
      description: 'Download and install the TypoSentinel extension from the VS Code marketplace.',
      action: 'Download Extension'
    },
    {
      label: 'Configure API Settings',
      description: 'Set up your API key and server URL in the extension settings.',
      action: 'Open Settings'
    },
    {
      label: 'Verify Connection',
      description: 'Test the connection to ensure the extension can communicate with TypoSentinel.',
      action: 'Test Connection'
    },
    {
      label: 'Start Scanning',
      description: 'Begin scanning your projects for typosquatting vulnerabilities.',
      action: 'Run Scan'
    }
  ];

  const features = [
    {
      title: 'Real-time Scanning',
      description: 'Automatically scan package.json files as you edit them',
      icon: <Security color="primary" />
    },
    {
      title: 'Inline Warnings',
      description: 'Get immediate feedback with inline warnings and suggestions',
      icon: <BugReport color="warning" />
    },
    {
      title: 'Quick Actions',
      description: 'Fix issues with one-click actions and automated suggestions',
      icon: <PlayArrow color="success" />
    },
    {
      title: 'Project Integration',
      description: 'Seamlessly integrate with your existing development workflow',
      icon: <Extension color="info" />
    }
  ];

  const mockScanResults = [
    {
      file: 'package.json',
      issues: 2,
      status: 'warning',
      packages: ['reqeust', 'lodsh']
    },
    {
      file: 'frontend/package.json',
      issues: 0,
      status: 'success',
      packages: []
    },
    {
      file: 'backend/package.json',
      issues: 1,
      status: 'error',
      packages: ['expres']
    }
  ];

  const handleNext = () => {
    setActiveStep((prevActiveStep) => prevActiveStep + 1);
  };

  const handleBack = () => {
    setActiveStep((prevActiveStep) => prevActiveStep - 1);
  };

  const handleReset = () => {
    setActiveStep(0);
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleStartScan = () => {
    setIsScanning(true);
    // Simulate scanning process
    setTimeout(() => {
      setIsScanning(false);
    }, 3000);
  };

  const handleCopyCommand = (command: string) => {
    navigator.clipboard.writeText(command);
  };

  const handleSaveConfig = () => {
    setConfigDialogOpen(false);
    // Save configuration logic here
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        VS Code Extension
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        Integrate TypoSentinel directly into your VS Code development environment for real-time typosquatting detection.
      </Typography>

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label="Installation" />
          <Tab label="Features" />
          <Tab label="Scanning" />
          <Tab label="Configuration" />
        </Tabs>
      </Box>

      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Installation Guide
                </Typography>
                <Stepper activeStep={activeStep} orientation="vertical">
                  {installationSteps.map((step, index) => (
                    <Step key={step.label}>
                      <StepLabel>
                        {step.label}
                      </StepLabel>
                      <StepContent>
                        <Typography>{step.description}</Typography>
                        <Box sx={{ mb: 2 }}>
                          <div>
                            <Button
                              variant="contained"
                              onClick={handleNext}
                              sx={{ mt: 1, mr: 1 }}
                              startIcon={
                                index === 0 ? <Download /> :
                                index === 1 ? <Settings /> :
                                index === 2 ? <CheckCircle /> :
                                <PlayArrow />
                              }
                            >
                              {step.action}
                            </Button>
                            <Button
                              disabled={index === 0}
                              onClick={handleBack}
                              sx={{ mt: 1, mr: 1 }}
                            >
                              Back
                            </Button>
                          </div>
                        </Box>
                      </StepContent>
                    </Step>
                  ))}
                </Stepper>
                {activeStep === installationSteps.length && (
                  <Paper square elevation={0} sx={{ p: 3 }}>
                    <Typography>All steps completed - you're ready to use TypoSentinel in VS Code!</Typography>
                    <Button onClick={handleReset} sx={{ mt: 1, mr: 1 }}>
                      Reset
                    </Button>
                  </Paper>
                )}
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Quick Commands
                </Typography>
                <List>
                  <ListItem>
                    <ListItemIcon>
                      <Terminal />
                    </ListItemIcon>
                    <ListItemText
                      primary="Install Extension"
                      secondary="code --install-extension typosentinel.vscode"
                    />
                    <Tooltip title="Copy command">
                      <IconButton onClick={() => handleCopyCommand('code --install-extension typosentinel.vscode')}>
                        <ContentCopy />
                      </IconButton>
                    </Tooltip>
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <Launch />
                    </ListItemIcon>
                    <ListItemText
                      primary="Open Marketplace"
                      secondary="Search for 'TypoSentinel'"
                    />
                    <Tooltip title="Open VS Code Marketplace">
                      <IconButton>
                        <Launch />
                      </IconButton>
                    </Tooltip>
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        <Grid container spacing={3}>
          {features.map((feature, index) => (
            <Grid item xs={12} md={6} key={index}>
              <Card sx={{ height: '100%' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    {feature.icon}
                    <Typography variant="h6" sx={{ ml: 1 }}>
                      {feature.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {feature.description}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Extension Commands
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <List>
                  <ListItem>
                    <ListItemText
                      primary="TypoSentinel: Scan Current File"
                      secondary="Ctrl+Shift+T S"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="TypoSentinel: Scan Workspace"
                      secondary="Ctrl+Shift+T W"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="TypoSentinel: Show Results"
                      secondary="Ctrl+Shift+T R"
                    />
                  </ListItem>
                </List>
              </Grid>
              <Grid item xs={12} md={6}>
                <List>
                  <ListItem>
                    <ListItemText
                      primary="TypoSentinel: Configure Settings"
                      secondary="Ctrl+Shift+T C"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="TypoSentinel: View Documentation"
                      secondary="Ctrl+Shift+T D"
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="TypoSentinel: Toggle Auto-scan"
                      secondary="Ctrl+Shift+T A"
                    />
                  </ListItem>
                </List>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">
                    Workspace Scan Results
                  </Typography>
                  <Box>
                    <Button
                      variant="contained"
                      onClick={handleStartScan}
                      disabled={isScanning}
                      startIcon={isScanning ? <Stop /> : <PlayArrow />}
                      sx={{ mr: 1 }}
                    >
                      {isScanning ? 'Scanning...' : 'Start Scan'}
                    </Button>
                    <Button
                      variant="outlined"
                      startIcon={<Refresh />}
                    >
                      Refresh
                    </Button>
                  </Box>
                </Box>
                
                {isScanning && (
                  <Alert severity="info" sx={{ mb: 2 }}>
                    Scanning workspace for typosquatting vulnerabilities...
                  </Alert>
                )}

                <List>
                  {mockScanResults.map((result, index) => (
                    <React.Fragment key={index}>
                      <ListItem>
                        <ListItemIcon>
                          <FilePresent />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              <Typography variant="body1" sx={{ mr: 1 }}>
                                {result.file}
                              </Typography>
                              <Chip
                                size="small"
                                label={`${result.issues} issues`}
                                color={
                                  result.status === 'success' ? 'success' :
                                  result.status === 'warning' ? 'warning' : 'error'
                                }
                              />
                            </Box>
                          }
                          secondary={
                            result.packages.length > 0 ?
                            `Suspicious packages: ${result.packages.join(', ')}` :
                            'No issues found'
                          }
                        />
                      </ListItem>
                      {index < mockScanResults.length - 1 && <Divider />}
                    </React.Fragment>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Scan Statistics
                </Typography>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    Files Scanned
                  </Typography>
                  <Typography variant="h4" color="primary">
                    3
                  </Typography>
                </Box>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    Issues Found
                  </Typography>
                  <Typography variant="h4" color="error">
                    3
                  </Typography>
                </Box>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    Last Scan
                  </Typography>
                  <Typography variant="body1">
                    2 minutes ago
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Extension Configuration
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Server URL"
                      value={serverUrl}
                      onChange={(e) => setServerUrl(e.target.value)}
                      helperText="TypoSentinel server endpoint"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="API Key"
                      type="password"
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      helperText="Your TypoSentinel API key"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Button
                      variant="contained"
                      onClick={() => setConfigDialogOpen(true)}
                      startIcon={<Settings />}
                    >
                      Advanced Settings
                    </Button>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Connection Status
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <CheckCircle color="success" sx={{ mr: 1 }} />
                  <Typography variant="body1">
                    Connected
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Extension is successfully connected to TypoSentinel server.
                </Typography>
                <Button
                  variant="outlined"
                  fullWidth
                  sx={{ mt: 2 }}
                  startIcon={<Refresh />}
                >
                  Test Connection
                </Button>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      <Dialog open={configDialogOpen} onClose={() => setConfigDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Advanced Configuration</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Scan Timeout (seconds)"
                type="number"
                defaultValue={30}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Max File Size (MB)"
                type="number"
                defaultValue={10}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Excluded Patterns"
                multiline
                rows={3}
                defaultValue="node_modules/**\n*.min.js\n*.bundle.js"
                helperText="One pattern per line"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleSaveConfig} variant="contained">Save</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default VSCodeExtension;
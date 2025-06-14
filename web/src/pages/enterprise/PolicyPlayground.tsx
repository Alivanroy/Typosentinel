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
  Paper,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tabs,
  Tab,
  LinearProgress,
  Breadcrumbs,
  Link,
  Tooltip,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Code as CodeIcon,
  BugReport as BugIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Settings as SettingsIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';

interface TestScenario {
  id: string;
  name: string;
  description: string;
  packageData: {
    name: string;
    version: string;
    ecosystem: string;
    vulnerabilities: any[];
    licenses: string[];
    maintainers: any[];
    lastUpdated: string;
    dependencies: any[];
  };
}

interface TestResult {
  id: string;
  scenarioId: string;
  timestamp: Date;
  status: 'passed' | 'failed' | 'warning';
  executionTime: number;
  ruleResults: RuleResult[];
  summary: {
    totalRules: number;
    passedRules: number;
    failedRules: number;
    warningRules: number;
  };
}

interface RuleResult {
  ruleId: string;
  ruleName: string;
  status: 'passed' | 'failed' | 'warning' | 'skipped';
  message: string;
  details?: any;
  executionTime: number;
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
      id={`playground-tabpanel-${index}`}
      aria-labelledby={`playground-tab-${index}`}
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

const PolicyPlayground: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [policy, setPolicy] = useState<any>(location.state?.policy || null);
  const [tabValue, setTabValue] = useState(0);
  const [selectedScenario, setSelectedScenario] = useState<TestScenario | null>(null);
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [customPackageData, setCustomPackageData] = useState('');
  const [testDialogOpen, setTestDialogOpen] = useState(false);

  // Mock test scenarios
  const [testScenarios] = useState<TestScenario[]>([
    {
      id: '1',
      name: 'Critical Vulnerability Package',
      description: 'Package with critical security vulnerabilities',
      packageData: {
        name: 'vulnerable-package',
        version: '1.0.0',
        ecosystem: 'npm',
        vulnerabilities: [
          {
            id: 'CVE-2023-1234',
            severity: 'critical',
            score: 9.8,
            description: 'Remote code execution vulnerability'
          }
        ],
        licenses: ['MIT'],
        maintainers: [{ name: 'John Doe', email: 'john@example.com' }],
        lastUpdated: '2023-01-01',
        dependencies: []
      }
    },
    {
      id: '2',
      name: 'Outdated Package',
      description: 'Package that hasn\'t been updated in over a year',
      packageData: {
        name: 'old-package',
        version: '0.5.0',
        ecosystem: 'npm',
        vulnerabilities: [],
        licenses: ['Apache-2.0'],
        maintainers: [{ name: 'Jane Smith', email: 'jane@example.com' }],
        lastUpdated: '2022-01-01',
        dependencies: []
      }
    },
    {
      id: '3',
      name: 'Unlicensed Package',
      description: 'Package without proper licensing information',
      packageData: {
        name: 'unlicensed-package',
        version: '2.1.0',
        ecosystem: 'npm',
        vulnerabilities: [],
        licenses: [],
        maintainers: [{ name: 'Anonymous', email: 'unknown@example.com' }],
        lastUpdated: '2023-06-01',
        dependencies: []
      }
    },
    {
      id: '4',
      name: 'Clean Package',
      description: 'Well-maintained package with no issues',
      packageData: {
        name: 'clean-package',
        version: '3.2.1',
        ecosystem: 'npm',
        vulnerabilities: [],
        licenses: ['MIT'],
        maintainers: [
          { name: 'Maintainer One', email: 'maintainer1@example.com' },
          { name: 'Maintainer Two', email: 'maintainer2@example.com' }
        ],
        lastUpdated: '2023-06-15',
        dependencies: []
      }
    }
  ]);

  useEffect(() => {
    if (!policy) {
      // Load a default policy for testing
      const defaultPolicy = {
        id: 'test-policy',
        name: 'Test Policy',
        rules: [
          {
            id: '1',
            name: 'Block Critical Vulnerabilities',
            type: 'vulnerability',
            severity: 'critical',
            enabled: true,
            conditions: [{ field: 'vulnerability.severity', operator: 'equals', value: 'critical' }],
            actions: [{ type: 'block', parameters: { message: 'Critical vulnerability detected' } }]
          }
        ]
      };
      setPolicy(defaultPolicy);
    }
  }, [policy]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const runTest = async (scenario: TestScenario) => {
    if (!policy) return;

    setIsRunning(true);
    setProgress(0);
    setSelectedScenario(scenario);

    try {
      // Simulate test execution
      const ruleResults: RuleResult[] = [];
      
      for (let i = 0; i < policy.rules.length; i++) {
        const rule = policy.rules[i];
        setProgress(((i + 1) / policy.rules.length) * 100);
        
        // Simulate rule execution delay
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Mock rule evaluation
        const result = evaluateRule(rule, scenario.packageData);
        ruleResults.push(result);
      }

      const testResult: TestResult = {
        id: Date.now().toString(),
        scenarioId: scenario.id,
        timestamp: new Date(),
        status: ruleResults.some(r => r.status === 'failed') ? 'failed' : 
                ruleResults.some(r => r.status === 'warning') ? 'warning' : 'passed',
        executionTime: policy.rules.length * 500,
        ruleResults,
        summary: {
          totalRules: ruleResults.length,
          passedRules: ruleResults.filter(r => r.status === 'passed').length,
          failedRules: ruleResults.filter(r => r.status === 'failed').length,
          warningRules: ruleResults.filter(r => r.status === 'warning').length
        }
      };

      setTestResults(prev => [testResult, ...prev]);
    } catch (error) {
      console.error('Test execution failed:', error);
    } finally {
      setIsRunning(false);
      setProgress(0);
    }
  };

  const evaluateRule = (rule: any, packageData: any): RuleResult => {
    const startTime = Date.now();
    
    // Mock rule evaluation logic
    let status: 'passed' | 'failed' | 'warning' | 'skipped' = 'passed';
    let message = 'Rule passed';
    
    if (!rule.enabled) {
      status = 'skipped';
      message = 'Rule is disabled';
    } else {
      // Evaluate conditions
      for (const condition of rule.conditions) {
        if (condition.field === 'vulnerability.severity' && condition.value === 'critical') {
          const hasCriticalVuln = packageData.vulnerabilities.some((v: any) => v.severity === 'critical');
          if (hasCriticalVuln) {
            status = 'failed';
            message = 'Critical vulnerability detected';
            break;
          }
        } else if (condition.field === 'package.lastUpdated' && condition.operator === 'less_than') {
          const lastUpdated = new Date(packageData.lastUpdated);
          const sixMonthsAgo = new Date();
          sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
          
          if (lastUpdated < sixMonthsAgo) {
            status = 'warning';
            message = 'Package is outdated';
          }
        }
      }
    }
    
    return {
      ruleId: rule.id,
      ruleName: rule.name,
      status,
      message,
      executionTime: Date.now() - startTime
    };
  };

  const runAllTests = async () => {
    for (const scenario of testScenarios) {
      await runTest(scenario);
    }
  };

  const handleCustomTest = () => {
    try {
      const packageData = JSON.parse(customPackageData);
      const customScenario: TestScenario = {
        id: 'custom',
        name: 'Custom Test',
        description: 'Custom package data test',
        packageData
      };
      runTest(customScenario);
      setTestDialogOpen(false);
    } catch (error) {
      alert('Invalid JSON format');
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'passed':
        return <CheckIcon color="success" />;
      case 'failed':
        return <ErrorIcon color="error" />;
      case 'warning':
        return <WarningIcon color="warning" />;
      default:
        return <InfoIcon color="info" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'passed':
        return 'success';
      case 'failed':
        return 'error';
      case 'warning':
        return 'warning';
      default:
        return 'info';
    }
  };

  if (!policy) {
    return <Box>Loading...</Box>;
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Breadcrumbs sx={{ mb: 2 }}>
          <Link color="inherit" onClick={() => navigate('/enterprise/policies')} sx={{ cursor: 'pointer' }}>
            Policies
          </Link>
          <Typography color="text.primary">
            Policy Playground
          </Typography>
        </Breadcrumbs>
        
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              Policy Playground
            </Typography>
            <Typography variant="body1" color="textSecondary">
              Test policy: <strong>{policy.name}</strong>
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="outlined"
              startIcon={<UploadIcon />}
              onClick={() => setTestDialogOpen(true)}
            >
              Custom Test
            </Button>
            <Button
              variant="contained"
              startIcon={<PlayIcon />}
              onClick={runAllTests}
              disabled={isRunning}
            >
              Run All Tests
            </Button>
          </Box>
        </Box>
      </Box>

      {/* Progress */}
      {isRunning && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="body2" gutterBottom>
            Running tests... {Math.round(progress)}%
          </Typography>
          <LinearProgress variant="determinate" value={progress} />
        </Box>
      )}

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label="Test Scenarios" />
          <Tab label="Test Results" />
          <Tab label="Policy Details" />
        </Tabs>
      </Box>

      {/* Test Scenarios Tab */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          {testScenarios.map((scenario) => {
            const latestResult = testResults.find(r => r.scenarioId === scenario.id);
            
            return (
              <Grid item xs={12} md={6} key={scenario.id}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="h6" gutterBottom>
                          {scenario.name}
                        </Typography>
                        <Typography variant="body2" color="textSecondary" gutterBottom>
                          {scenario.description}
                        </Typography>
                        {latestResult && (
                          <Chip
                            icon={getStatusIcon(latestResult.status)}
                            label={latestResult.status.toUpperCase()}
                            color={getStatusColor(latestResult.status) as any}
                            size="small"
                          />
                        )}
                      </Box>
                      <Button
                        variant="contained"
                        size="small"
                        startIcon={<PlayIcon />}
                        onClick={() => runTest(scenario)}
                        disabled={isRunning}
                      >
                        Test
                      </Button>
                    </Box>
                    
                    <Divider sx={{ my: 2 }} />
                    
                    <Typography variant="subtitle2" gutterBottom>
                      Package Details
                    </Typography>
                    <Grid container spacing={1}>
                      <Grid item xs={6}>
                        <Typography variant="body2">
                          <strong>Name:</strong> {scenario.packageData.name}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2">
                          <strong>Version:</strong> {scenario.packageData.version}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2">
                          <strong>Ecosystem:</strong> {scenario.packageData.ecosystem}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2">
                          <strong>Vulnerabilities:</strong> {scenario.packageData.vulnerabilities.length}
                        </Typography>
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      </TabPanel>

      {/* Test Results Tab */}
      <TabPanel value={tabValue} index={1}>
        {testResults.length === 0 ? (
          <Card>
            <CardContent sx={{ textAlign: 'center', py: 6 }}>
              <Typography variant="h6" color="textSecondary" gutterBottom>
                No test results yet
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                Run some tests to see the results here
              </Typography>
              <Button
                variant="contained"
                startIcon={<PlayIcon />}
                onClick={runAllTests}
              >
                Run All Tests
              </Button>
            </CardContent>
          </Card>
        ) : (
          <Grid container spacing={3}>
            {testResults.map((result) => {
              const scenario = testScenarios.find(s => s.id === result.scenarioId);
              
              return (
                <Grid item xs={12} key={result.id}>
                  <Card>
                    <CardContent>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                        <Box>
                          <Typography variant="h6" gutterBottom>
                            {scenario?.name || 'Unknown Scenario'}
                          </Typography>
                          <Typography variant="body2" color="textSecondary">
                            Executed at {result.timestamp.toLocaleString()}
                          </Typography>
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Chip
                            icon={getStatusIcon(result.status)}
                            label={result.status.toUpperCase()}
                            color={getStatusColor(result.status) as any}
                          />
                          <Typography variant="body2" color="textSecondary">
                            {result.executionTime}ms
                          </Typography>
                        </Box>
                      </Box>
                      
                      <Grid container spacing={2} sx={{ mb: 2 }}>
                        <Grid item xs={3}>
                          <Typography variant="body2" align="center">
                            <strong>{result.summary.totalRules}</strong><br />
                            Total Rules
                          </Typography>
                        </Grid>
                        <Grid item xs={3}>
                          <Typography variant="body2" align="center" color="success.main">
                            <strong>{result.summary.passedRules}</strong><br />
                            Passed
                          </Typography>
                        </Grid>
                        <Grid item xs={3}>
                          <Typography variant="body2" align="center" color="warning.main">
                            <strong>{result.summary.warningRules}</strong><br />
                            Warnings
                          </Typography>
                        </Grid>
                        <Grid item xs={3}>
                          <Typography variant="body2" align="center" color="error.main">
                            <strong>{result.summary.failedRules}</strong><br />
                            Failed
                          </Typography>
                        </Grid>
                      </Grid>
                      
                      <Accordion>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                          <Typography variant="subtitle2">
                            Rule Results ({result.ruleResults.length})
                          </Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          <List dense>
                            {result.ruleResults.map((ruleResult) => (
                              <ListItem key={ruleResult.ruleId}>
                                <ListItemIcon>
                                  {getStatusIcon(ruleResult.status)}
                                </ListItemIcon>
                                <ListItemText
                                  primary={ruleResult.ruleName}
                                  secondary={`${ruleResult.message} (${ruleResult.executionTime}ms)`}
                                />
                              </ListItem>
                            ))}
                          </List>
                        </AccordionDetails>
                      </Accordion>
                    </CardContent>
                  </Card>
                </Grid>
              );
            })}
          </Grid>
        )}
      </TabPanel>

      {/* Policy Details Tab */}
      <TabPanel value={tabValue} index={2}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Policy Configuration
                </Typography>
                <Paper sx={{ p: 2, bgcolor: 'grey.50', maxHeight: 400, overflow: 'auto' }}>
                  <pre style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem', margin: 0 }}>
                    {JSON.stringify(policy, null, 2)}
                  </pre>
                </Paper>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Policy Summary
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemText
                      primary="Total Rules"
                      secondary={policy.rules?.length || 0}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Active Rules"
                      secondary={policy.rules?.filter((r: any) => r.enabled).length || 0}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Policy Status"
                      secondary={policy.status || 'Unknown'}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Version"
                      secondary={policy.version || '1.0.0'}
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Custom Test Dialog */}
      <Dialog
        open={testDialogOpen}
        onClose={() => setTestDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Custom Package Test</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="textSecondary" gutterBottom>
            Enter package data in JSON format to test against the current policy.
          </Typography>
          <TextField
            fullWidth
            multiline
            rows={12}
            value={customPackageData}
            onChange={(e) => setCustomPackageData(e.target.value)}
            placeholder={JSON.stringify({
              name: 'example-package',
              version: '1.0.0',
              ecosystem: 'npm',
              vulnerabilities: [],
              licenses: ['MIT'],
              maintainers: [{ name: 'John Doe', email: 'john@example.com' }],
              lastUpdated: '2023-06-01',
              dependencies: []
            }, null, 2)}
            sx={{ mt: 2, fontFamily: 'monospace' }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTestDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleCustomTest}
            variant="contained"
            disabled={!customPackageData.trim()}
          >
            Run Test
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default PolicyPlayground;
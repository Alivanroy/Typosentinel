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
} from '@mui/material';
import {
  Save as SaveIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  ExpandMore as ExpandMoreIcon,
  Code as CodeIcon,
  PlayArrow as PlayIcon,
  Visibility as PreviewIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Help as HelpIcon,
  Warning as WarningIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import { useNavigate, useParams } from 'react-router-dom';

interface PolicyRule {
  id: string;
  name: string;
  description: string;
  type: 'vulnerability' | 'license' | 'dependency' | 'maintainer' | 'custom';
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  conditions: PolicyCondition[];
  actions: PolicyAction[];
}

interface PolicyCondition {
  id: string;
  field: string;
  operator: 'equals' | 'contains' | 'greater_than' | 'less_than' | 'in' | 'not_in';
  value: string | number | string[];
  logicalOperator?: 'AND' | 'OR';
}

interface PolicyAction {
  id: string;
  type: 'block' | 'warn' | 'notify' | 'quarantine' | 'auto_fix';
  parameters: Record<string, any>;
}

interface Policy {
  id: string;
  name: string;
  description: string;
  version: string;
  status: 'draft' | 'active' | 'inactive';
  createdAt: Date;
  updatedAt: Date;
  author: string;
  rules: PolicyRule[];
  metadata: {
    tags: string[];
    category: string;
    priority: number;
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
      id={`policy-editor-tabpanel-${index}`}
      aria-labelledby={`policy-editor-tab-${index}`}
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

const PolicyEditor: React.FC = () => {
  const navigate = useNavigate();
  const { policyId } = useParams<{ policyId?: string }>();
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(false);
  const [saveDialogOpen, setSaveDialogOpen] = useState(false);
  const [previewDialogOpen, setPreviewDialogOpen] = useState(false);
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<PolicyRule | null>(null);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  // Mock policy data
  useEffect(() => {
    if (policyId && policyId !== 'new') {
      // Load existing policy
      const mockPolicy: Policy = {
        id: policyId,
        name: 'Security Compliance Policy',
        description: 'Comprehensive security policy for package management',
        version: '1.2.0',
        status: 'active',
        createdAt: new Date('2023-06-01'),
        updatedAt: new Date('2023-06-14'),
        author: 'Security Team',
        metadata: {
          tags: ['security', 'compliance', 'npm'],
          category: 'Security',
          priority: 1
        },
        rules: [
          {
            id: '1',
            name: 'Block Critical Vulnerabilities',
            description: 'Automatically block packages with critical vulnerabilities',
            type: 'vulnerability',
            severity: 'critical',
            enabled: true,
            conditions: [
              {
                id: '1',
                field: 'vulnerability.severity',
                operator: 'equals',
                value: 'critical'
              }
            ],
            actions: [
              {
                id: '1',
                type: 'block',
                parameters: {
                  message: 'Package blocked due to critical vulnerability'
                }
              }
            ]
          },
          {
            id: '2',
            name: 'Warn on Outdated Packages',
            description: 'Warn when packages are more than 6 months old',
            type: 'dependency',
            severity: 'medium',
            enabled: true,
            conditions: [
              {
                id: '1',
                field: 'package.lastUpdated',
                operator: 'less_than',
                value: '6 months'
              }
            ],
            actions: [
              {
                id: '1',
                type: 'warn',
                parameters: {
                  message: 'Package is outdated and may have security issues'
                }
              }
            ]
          }
        ]
      };
      setPolicy(mockPolicy);
    } else {
      // Create new policy
      const newPolicy: Policy = {
        id: 'new',
        name: '',
        description: '',
        version: '1.0.0',
        status: 'draft',
        createdAt: new Date(),
        updatedAt: new Date(),
        author: 'Current User',
        metadata: {
          tags: [],
          category: '',
          priority: 1
        },
        rules: []
      };
      setPolicy(newPolicy);
    }
  }, [policyId]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleSave = async () => {
    if (!policy) return;
    
    setLoading(true);
    try {
      // Validate policy
      const errors = validatePolicy(policy);
      if (errors.length > 0) {
        setValidationErrors(errors);
        return;
      }

      // Save policy (mock)
      console.log('Saving policy:', policy);
      setSaveDialogOpen(true);
    } catch (error) {
      console.error('Failed to save policy:', error);
    } finally {
      setLoading(false);
    }
  };

  const validatePolicy = (policy: Policy): string[] => {
    const errors: string[] = [];
    
    if (!policy.name.trim()) {
      errors.push('Policy name is required');
    }
    
    if (!policy.description.trim()) {
      errors.push('Policy description is required');
    }
    
    if (policy.rules.length === 0) {
      errors.push('At least one rule is required');
    }
    
    policy.rules.forEach((rule, index) => {
      if (!rule.name.trim()) {
        errors.push(`Rule ${index + 1}: Name is required`);
      }
      if (rule.conditions.length === 0) {
        errors.push(`Rule ${index + 1}: At least one condition is required`);
      }
      if (rule.actions.length === 0) {
        errors.push(`Rule ${index + 1}: At least one action is required`);
      }
    });
    
    return errors;
  };

  const handleAddRule = () => {
    const newRule: PolicyRule = {
      id: Date.now().toString(),
      name: '',
      description: '',
      type: 'vulnerability',
      severity: 'medium',
      enabled: true,
      conditions: [],
      actions: []
    };
    setSelectedRule(newRule);
    setRuleDialogOpen(true);
  };

  const handleEditRule = (rule: PolicyRule) => {
    setSelectedRule(rule);
    setRuleDialogOpen(true);
  };

  const handleDeleteRule = (ruleId: string) => {
    if (!policy) return;
    setPolicy({
      ...policy,
      rules: policy.rules.filter(rule => rule.id !== ruleId)
    });
  };

  const handleRuleSave = (rule: PolicyRule) => {
    if (!policy) return;
    
    const existingRuleIndex = policy.rules.findIndex(r => r.id === rule.id);
    if (existingRuleIndex >= 0) {
      // Update existing rule
      const updatedRules = [...policy.rules];
      updatedRules[existingRuleIndex] = rule;
      setPolicy({ ...policy, rules: updatedRules });
    } else {
      // Add new rule
      setPolicy({ ...policy, rules: [...policy.rules, rule] });
    }
    setRuleDialogOpen(false);
  };

  const handleTestPolicy = () => {
    // Navigate to policy playground for testing
    navigate('/enterprise/policies/playground', { state: { policy } });
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
            {policyId === 'new' ? 'New Policy' : policy.name}
          </Typography>
        </Breadcrumbs>
        
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h4" component="h1">
            Policy Editor
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="outlined"
              startIcon={<PlayIcon />}
              onClick={handleTestPolicy}
            >
              Test Policy
            </Button>
            <Button
              variant="outlined"
              startIcon={<PreviewIcon />}
              onClick={() => setPreviewDialogOpen(true)}
            >
              Preview
            </Button>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleSave}
              disabled={loading}
            >
              Save Policy
            </Button>
          </Box>
        </Box>
      </Box>

      {/* Validation Errors */}
      {validationErrors.length > 0 && (
        <Alert severity="error" sx={{ mb: 3 }}>
          <Typography variant="subtitle2" gutterBottom>
            Please fix the following errors:
          </Typography>
          <ul style={{ margin: 0, paddingLeft: 20 }}>
            {validationErrors.map((error, index) => (
              <li key={index}>{error}</li>
            ))}
          </ul>
        </Alert>
      )}

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label="General" />
          <Tab label="Rules" />
          <Tab label="Advanced" />
        </Tabs>
      </Box>

      {/* General Tab */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Policy Information
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Policy Name"
                      value={policy.name}
                      onChange={(e) => setPolicy({ ...policy, name: e.target.value })}
                      required
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Description"
                      value={policy.description}
                      onChange={(e) => setPolicy({ ...policy, description: e.target.value })}
                      multiline
                      rows={3}
                      required
                    />
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="Version"
                      value={policy.version}
                      onChange={(e) => setPolicy({ ...policy, version: e.target.value })}
                    />
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth>
                      <InputLabel>Status</InputLabel>
                      <Select
                        value={policy.status}
                        label="Status"
                        onChange={(e) => setPolicy({ ...policy, status: e.target.value as any })}
                      >
                        <MenuItem value="draft">Draft</MenuItem>
                        <MenuItem value="active">Active</MenuItem>
                        <MenuItem value="inactive">Inactive</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Metadata
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Category"
                      value={policy.metadata.category}
                      onChange={(e) => setPolicy({
                        ...policy,
                        metadata: { ...policy.metadata, category: e.target.value }
                      })}
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Priority"
                      type="number"
                      value={policy.metadata.priority}
                      onChange={(e) => setPolicy({
                        ...policy,
                        metadata: { ...policy.metadata, priority: parseInt(e.target.value) }
                      })}
                      inputProps={{ min: 1, max: 10 }}
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Tags (comma-separated)"
                      value={policy.metadata.tags.join(', ')}
                      onChange={(e) => setPolicy({
                        ...policy,
                        metadata: {
                          ...policy.metadata,
                          tags: e.target.value.split(',').map(tag => tag.trim()).filter(tag => tag)
                        }
                      })}
                    />
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Rules Tab */}
      <TabPanel value={tabValue} index={1}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h6">
            Policy Rules ({policy.rules.length})
          </Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleAddRule}
          >
            Add Rule
          </Button>
        </Box>

        {policy.rules.length === 0 ? (
          <Card>
            <CardContent sx={{ textAlign: 'center', py: 6 }}>
              <Typography variant="h6" color="textSecondary" gutterBottom>
                No rules defined
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 3 }}>
                Add rules to define how this policy should behave
              </Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={handleAddRule}
              >
                Add First Rule
              </Button>
            </CardContent>
          </Card>
        ) : (
          <Grid container spacing={2}>
            {policy.rules.map((rule, index) => (
              <Grid item xs={12} key={rule.id}>
                <Card>
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                      <Box sx={{ flex: 1 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                          <Typography variant="h6">
                            {rule.name || `Rule ${index + 1}`}
                          </Typography>
                          <Chip
                            label={rule.type}
                            size="small"
                            color="primary"
                          />
                          <Chip
                            label={rule.severity}
                            size="small"
                            color={rule.severity === 'critical' ? 'error' : rule.severity === 'high' ? 'warning' : 'default'}
                          />
                          <Switch
                            checked={rule.enabled}
                            onChange={(e) => {
                              const updatedRules = policy.rules.map(r => 
                                r.id === rule.id ? { ...r, enabled: e.target.checked } : r
                              );
                              setPolicy({ ...policy, rules: updatedRules });
                            }}
                            size="small"
                          />
                        </Box>
                        <Typography variant="body2" color="textSecondary">
                          {rule.description}
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <IconButton
                          size="small"
                          onClick={() => handleEditRule(rule)}
                        >
                          <EditIcon />
                        </IconButton>
                        <IconButton
                          size="small"
                          onClick={() => handleDeleteRule(rule.id)}
                          color="error"
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Box>
                    </Box>
                    
                    <Divider sx={{ my: 2 }} />
                    
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <Typography variant="subtitle2" gutterBottom>
                          Conditions ({rule.conditions.length})
                        </Typography>
                        {rule.conditions.map((condition, condIndex) => (
                          <Chip
                            key={condition.id}
                            label={`${condition.field} ${condition.operator} ${condition.value}`}
                            size="small"
                            variant="outlined"
                            sx={{ mr: 0.5, mb: 0.5 }}
                          />
                        ))}
                      </Grid>
                      <Grid item xs={12} md={6}>
                        <Typography variant="subtitle2" gutterBottom>
                          Actions ({rule.actions.length})
                        </Typography>
                        {rule.actions.map((action, actionIndex) => (
                          <Chip
                            key={action.id}
                            label={action.type}
                            size="small"
                            variant="outlined"
                            color={action.type === 'block' ? 'error' : action.type === 'warn' ? 'warning' : 'default'}
                            sx={{ mr: 0.5, mb: 0.5 }}
                          />
                        ))}
                      </Grid>
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}
      </TabPanel>

      {/* Advanced Tab */}
      <TabPanel value={tabValue} index={2}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Export/Import
                </Typography>
                <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                  <Button
                    variant="outlined"
                    startIcon={<DownloadIcon />}
                    fullWidth
                  >
                    Export Policy
                  </Button>
                  <Button
                    variant="outlined"
                    startIcon={<UploadIcon />}
                    fullWidth
                  >
                    Import Policy
                  </Button>
                </Box>
                <Typography variant="body2" color="textSecondary">
                  Export policies as JSON or YAML files, or import existing policies.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Policy Templates
                </Typography>
                <List dense>
                  <ListItem button>
                    <ListItemText
                      primary="Security Baseline"
                      secondary="Standard security rules for most projects"
                    />
                  </ListItem>
                  <ListItem button>
                    <ListItemText
                      primary="Compliance Template"
                      secondary="Rules for regulatory compliance"
                    />
                  </ListItem>
                  <ListItem button>
                    <ListItemText
                      primary="Open Source Policy"
                      secondary="Guidelines for open source package usage"
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Save Dialog */}
      <Dialog open={saveDialogOpen} onClose={() => setSaveDialogOpen(false)}>
        <DialogTitle>Policy Saved</DialogTitle>
        <DialogContent>
          <Typography>
            The policy "{policy.name}" has been saved successfully.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSaveDialogOpen(false)}>Close</Button>
          <Button onClick={() => navigate('/enterprise/policies')} variant="contained">
            Back to Policies
          </Button>
        </DialogActions>
      </Dialog>

      {/* Preview Dialog */}
      <Dialog
        open={previewDialogOpen}
        onClose={() => setPreviewDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Policy Preview</DialogTitle>
        <DialogContent>
          <Paper sx={{ p: 2, bgcolor: 'grey.50' }}>
            <pre style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem' }}>
              {JSON.stringify(policy, null, 2)}
            </pre>
          </Paper>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPreviewDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default PolicyEditor;
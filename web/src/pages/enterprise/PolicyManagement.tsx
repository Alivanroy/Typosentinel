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
  Switch,
  FormControlLabel,
  Alert,
  Tabs,
  Tab,
  Divider,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  PlayArrow as PlayIcon,
  Code as CodeIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  FileCopy as CopyIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

interface Policy {
  id: string;
  name: string;
  description: string;
  category: 'typosquatting' | 'malware' | 'supply-chain' | 'custom';
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  version: string;
  author: string;
  createdAt: Date;
  updatedAt: Date;
  rules: string; // Rego policy content
  testCases: Array<{
    name: string;
    input: any;
    expectedOutput: boolean;
  }>;
  usage: {
    scansApplied: number;
    violationsFound: number;
    lastUsed: Date;
  };
}

interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  template: string;
  variables: Array<{
    name: string;
    type: 'string' | 'number' | 'boolean' | 'array';
    description: string;
    defaultValue?: any;
  }>;
}

const PolicyManagement: React.FC = () => {
  const navigate = useNavigate();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTab, setSelectedTab] = useState(0);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null);
  const [newPolicy, setNewPolicy] = useState({
    name: '',
    description: '',
    category: 'custom' as const,
    severity: 'medium' as const,
    template: '',
  });

  useEffect(() => {
    loadPolicies();
    loadTemplates();
  }, []);

  const loadPolicies = async () => {
    try {
      // Simulate API call - replace with actual API
      const mockPolicies: Policy[] = [
        {
          id: '1',
          name: 'Typosquatting Detection',
          description: 'Detects packages that may be typosquatting popular packages',
          category: 'typosquatting',
          severity: 'high',
          enabled: true,
          version: '1.2.0',
          author: 'TypoSentinel Team',
          createdAt: new Date('2025-01-15'),
          updatedAt: new Date('2025-06-10'),
          rules: `package typosquatting

default allow = false

allow {
    input.package.name
    similar_to_popular_package
    not whitelisted_package
}

similar_to_popular_package {
    popular_packages := ["lodash", "express", "react", "vue"]
    some popular in popular_packages
    levenshtein_distance(input.package.name, popular) <= 2
    input.package.name != popular
}

whitelisted_package {
    whitelist := ["lodash-es", "express-validator"]
    input.package.name in whitelist
}`,
          testCases: [
            {
              name: 'Detect lodahs typosquatting',
              input: { package: { name: 'lodahs' } },
              expectedOutput: true,
            },
            {
              name: 'Allow legitimate lodash',
              input: { package: { name: 'lodash' } },
              expectedOutput: false,
            },
          ],
          usage: {
            scansApplied: 1247,
            violationsFound: 23,
            lastUsed: new Date('2025-06-14'),
          },
        },
        {
          id: '2',
          name: 'Cryptocurrency Mining Detection',
          description: 'Identifies packages that contain cryptocurrency mining code',
          category: 'malware',
          severity: 'critical',
          enabled: true,
          version: '1.0.0',
          author: 'Security Team',
          createdAt: new Date('2025-02-01'),
          updatedAt: new Date('2025-06-12'),
          rules: `package crypto_mining

default allow = false

allow {
    contains_mining_keywords
    not legitimate_crypto_package
}

contains_mining_keywords {
    keywords := ["mine", "miner", "mining", "hashrate", "cryptocurrency"]
    some keyword in keywords
    contains(lower(input.package.description), keyword)
}

legitimate_crypto_package {
    legitimate := ["crypto-js", "node-crypto"]
    input.package.name in legitimate
}`,
          testCases: [
            {
              name: 'Detect mining package',
              input: { package: { name: 'crypto-miner', description: 'Bitcoin mining utility' } },
              expectedOutput: true,
            },
          ],
          usage: {
            scansApplied: 892,
            violationsFound: 12,
            lastUsed: new Date('2025-06-13'),
          },
        },
        {
          id: '3',
          name: 'Data Exfiltration Prevention',
          description: 'Prevents packages that attempt to exfiltrate sensitive data',
          category: 'malware',
          severity: 'critical',
          enabled: false,
          version: '0.9.0',
          author: 'Security Team',
          createdAt: new Date('2025-03-10'),
          updatedAt: new Date('2025-06-08'),
          rules: `package data_exfiltration

default allow = false

allow {
    suspicious_network_activity
    accesses_sensitive_files
}

suspicious_network_activity {
    input.analysis.network_requests
    count(input.analysis.network_requests) > 5
}

accesses_sensitive_files {
    sensitive_paths := ["/etc/passwd", "~/.ssh", "~/.aws"]
    some path in sensitive_paths
    path in input.analysis.file_access
}`,
          testCases: [],
          usage: {
            scansApplied: 456,
            violationsFound: 8,
            lastUsed: new Date('2025-06-11'),
          },
        },
      ];
      
      setPolicies(mockPolicies);
    } catch (error) {
      console.error('Failed to load policies:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadTemplates = async () => {
    try {
      // Simulate API call - replace with actual API
      const mockTemplates: PolicyTemplate[] = [
        {
          id: '1',
          name: 'Basic Typosquatting Detection',
          description: 'Template for detecting typosquatting attacks',
          category: 'typosquatting',
          template: `package {{.package_name}}

default allow = false

allow {
    input.package.name
    similar_to_popular_package
    not whitelisted_package
}

similar_to_popular_package {
    popular_packages := {{.popular_packages}}
    some popular in popular_packages
    levenshtein_distance(input.package.name, popular) <= {{.max_distance}}
    input.package.name != popular
}`,
          variables: [
            {
              name: 'package_name',
              type: 'string',
              description: 'Name of the policy package',
              defaultValue: 'typosquatting_detection',
            },
            {
              name: 'popular_packages',
              type: 'array',
              description: 'List of popular packages to protect',
              defaultValue: ['lodash', 'express', 'react'],
            },
            {
              name: 'max_distance',
              type: 'number',
              description: 'Maximum Levenshtein distance for similarity',
              defaultValue: 2,
            },
          ],
        },
        {
          id: '2',
          name: 'Malware Detection',
          description: 'Template for detecting malicious packages',
          category: 'malware',
          template: `package {{.package_name}}

default allow = false

allow {
    contains_suspicious_keywords
    not whitelisted_package
}

contains_suspicious_keywords {
    keywords := {{.suspicious_keywords}}
    some keyword in keywords
    contains(lower(input.package.description), keyword)
}`,
          variables: [
            {
              name: 'package_name',
              type: 'string',
              description: 'Name of the policy package',
              defaultValue: 'malware_detection',
            },
            {
              name: 'suspicious_keywords',
              type: 'array',
              description: 'Keywords that indicate malicious intent',
              defaultValue: ['malware', 'virus', 'trojan'],
            },
          ],
        },
      ];
      
      setTemplates(mockTemplates);
    } catch (error) {
      console.error('Failed to load templates:', error);
    }
  };

  const handleCreatePolicy = async () => {
    try {
      // Simulate API call - replace with actual API
      const policy: Policy = {
        id: Date.now().toString(),
        name: newPolicy.name,
        description: newPolicy.description,
        category: newPolicy.category,
        severity: newPolicy.severity,
        enabled: false,
        version: '1.0.0',
        author: 'Current User',
        createdAt: new Date(),
        updatedAt: new Date(),
        rules: newPolicy.template || '// New policy rules',
        testCases: [],
        usage: {
          scansApplied: 0,
          violationsFound: 0,
          lastUsed: new Date(),
        },
      };
      
      setPolicies(prev => [policy, ...prev]);
      setCreateDialogOpen(false);
      setNewPolicy({
        name: '',
        description: '',
        category: 'custom',
        severity: 'medium',
        template: '',
      });
    } catch (error) {
      console.error('Failed to create policy:', error);
    }
  };

  const handleDeletePolicy = async () => {
    if (!selectedPolicy) return;
    
    try {
      // Simulate API call - replace with actual API
      setPolicies(prev => prev.filter(p => p.id !== selectedPolicy.id));
      setDeleteDialogOpen(false);
      setSelectedPolicy(null);
    } catch (error) {
      console.error('Failed to delete policy:', error);
    }
  };

  const handleTogglePolicy = async (policyId: string, enabled: boolean) => {
    try {
      // Simulate API call - replace with actual API
      setPolicies(prev => prev.map(p => 
        p.id === policyId ? { ...p, enabled } : p
      ));
    } catch (error) {
      console.error('Failed to toggle policy:', error);
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

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'typosquatting': return <SecurityIcon />;
      case 'malware': return <WarningIcon />;
      case 'supply-chain': return <CheckCircleIcon />;
      default: return <CodeIcon />;
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          Policy Management
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button 
            variant="outlined" 
            startIcon={<UploadIcon />}
            onClick={() => {
              // Handle import functionality
              console.log('Import policies');
            }}
          >
            Import
          </Button>
          <Button 
            variant="outlined" 
            startIcon={<DownloadIcon />}
            onClick={() => {
              // Handle export functionality
              console.log('Export policies');
            }}
          >
            Export
          </Button>
          <Button 
            variant="contained" 
            startIcon={<AddIcon />}
            onClick={() => setCreateDialogOpen(true)}
          >
            Create Policy
          </Button>
        </Box>
      </Box>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={selectedTab} onChange={(_, newValue) => setSelectedTab(newValue)}>
          <Tab label="Active Policies" />
          <Tab label="Policy Templates" />
          <Tab label="Policy Builder" />
        </Tabs>
      </Box>

      {/* Active Policies Tab */}
      {selectedTab === 0 && (
        <Grid container spacing={3}>
          {/* Summary Cards */}
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Total Policies
                </Typography>
                <Typography variant="h4">
                  {policies.length}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Active Policies
                </Typography>
                <Typography variant="h4" color="success.main">
                  {policies.filter(p => p.enabled).length}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Total Violations
                </Typography>
                <Typography variant="h4" color="error.main">
                  {policies.reduce((sum, p) => sum + p.usage.violationsFound, 0)}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Scans Applied
                </Typography>
                <Typography variant="h4">
                  {policies.reduce((sum, p) => sum + p.usage.scansApplied, 0).toLocaleString()}
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          {/* Policies Table */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">
                    Policy Rules
                  </Typography>
                  <IconButton onClick={loadPolicies}>
                    <RefreshIcon />
                  </IconButton>
                </Box>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Policy</TableCell>
                        <TableCell>Category</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Version</TableCell>
                        <TableCell>Usage</TableCell>
                        <TableCell>Last Updated</TableCell>
                        <TableCell>Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {policies.map((policy) => (
                        <TableRow key={policy.id}>
                          <TableCell>
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              {getCategoryIcon(policy.category)}
                              <Box sx={{ ml: 1 }}>
                                <Typography variant="body2" fontWeight={500}>
                                  {policy.name}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {policy.description}
                                </Typography>
                              </Box>
                            </Box>
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={policy.category} 
                              variant="outlined"
                              size="small"
                            />
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={policy.severity.toUpperCase()} 
                              color={getSeverityColor(policy.severity) as any}
                              size="small"
                            />
                          </TableCell>
                          <TableCell>
                            <FormControlLabel
                              control={
                                <Switch 
                                  checked={policy.enabled}
                                  onChange={(e) => handleTogglePolicy(policy.id, e.target.checked)}
                                  size="small"
                                />
                              }
                              label={policy.enabled ? 'Active' : 'Inactive'}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2">
                              v{policy.version}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2">
                              {policy.usage.scansApplied.toLocaleString()} scans
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {policy.usage.violationsFound} violations
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2">
                              {policy.updatedAt.toLocaleDateString()}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Box sx={{ display: 'flex', gap: 0.5 }}>
                              <Tooltip title="Test policy">
                                <IconButton 
                                  size="small"
                                  onClick={() => navigate('/enterprise/policies/playground', { 
                                    state: { policy } 
                                  })}
                                >
                                  <PlayIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="Edit policy">
                                <IconButton 
                                  size="small"
                                  onClick={() => navigate('/enterprise/policies/editor', { 
                                    state: { policy } 
                                  })}
                                >
                                  <EditIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="Copy policy">
                                <IconButton size="small">
                                  <CopyIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                              <Tooltip title="Delete policy">
                                <IconButton 
                                  size="small"
                                  color="error"
                                  onClick={() => {
                                    setSelectedPolicy(policy);
                                    setDeleteDialogOpen(true);
                                  }}
                                >
                                  <DeleteIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                            </Box>
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

      {/* Policy Templates Tab */}
      {selectedTab === 1 && (
        <Grid container spacing={3}>
          {templates.map((template) => (
            <Grid item xs={12} md={6} lg={4} key={template.id}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    {template.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {template.description}
                  </Typography>
                  <Chip 
                    label={template.category} 
                    variant="outlined"
                    size="small"
                    sx={{ mb: 2 }}
                  />
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Button 
                      size="small" 
                      variant="outlined"
                      onClick={() => {
                        setNewPolicy(prev => ({
                          ...prev,
                          template: template.template,
                          category: template.category as any,
                        }));
                        setCreateDialogOpen(true);
                      }}
                    >
                      Use Template
                    </Button>
                    <Button 
                      size="small" 
                      variant="text"
                      onClick={() => navigate('/enterprise/policies/editor', { 
                        state: { template } 
                      })}
                    >
                      Customize
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Policy Builder Tab */}
      {selectedTab === 2 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Guided Policy Builder
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Create custom policies using our guided builder interface.
            </Typography>
            <Button 
              variant="contained" 
              onClick={() => navigate('/enterprise/policies/editor', { 
                state: { mode: 'guided' } 
              })}
            >
              Launch Policy Builder
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Create Policy Dialog */}
      <Dialog open={createDialogOpen} onClose={() => setCreateDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create New Policy</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <TextField
              fullWidth
              label="Policy Name"
              value={newPolicy.name}
              onChange={(e) => setNewPolicy(prev => ({ ...prev, name: e.target.value }))}
              sx={{ mb: 2 }}
            />
            <TextField
              fullWidth
              label="Description"
              multiline
              rows={3}
              value={newPolicy.description}
              onChange={(e) => setNewPolicy(prev => ({ ...prev, description: e.target.value }))}
              sx={{ mb: 2 }}
            />
            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Category</InputLabel>
                  <Select
                    value={newPolicy.category}
                    label="Category"
                    onChange={(e) => setNewPolicy(prev => ({ ...prev, category: e.target.value as any }))}
                  >
                    <MenuItem value="typosquatting">Typosquatting</MenuItem>
                    <MenuItem value="malware">Malware</MenuItem>
                    <MenuItem value="supply-chain">Supply Chain</MenuItem>
                    <MenuItem value="custom">Custom</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Severity</InputLabel>
                  <Select
                    value={newPolicy.severity}
                    label="Severity"
                    onChange={(e) => setNewPolicy(prev => ({ ...prev, severity: e.target.value as any }))}
                  >
                    <MenuItem value="low">Low</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          <Button 
            onClick={handleCreatePolicy} 
            variant="contained"
            disabled={!newPolicy.name || !newPolicy.description}
          >
            Create Policy
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Policy Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete Policy</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the policy "{selectedPolicy?.name}"? This action cannot be undone.
          </Typography>
          {selectedPolicy?.enabled && (
            <Alert severity="warning" sx={{ mt: 2 }}>
              This policy is currently active and will be removed from all scans.
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleDeletePolicy} color="error" variant="contained">
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default PolicyManagement;
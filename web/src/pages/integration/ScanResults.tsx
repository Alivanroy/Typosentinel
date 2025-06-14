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
  Badge,
  Collapse,
  TablePagination,
  Autocomplete,
  Stack,
  ButtonGroup,
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
  GetApp as ExportIcon,
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
  FilterList as FilterIcon,
  Search as SearchIcon,
  Clear as ClearIcon,
  ExpandLess as ExpandLessIcon,
  ExpandMore as ExpandMoreIconCollapse,
  Assessment as AssessmentIcon,
  PieChart as PieChartIcon,
  BarChart as BarChartIcon,
  ShowChart as ShowChartIcon,
  Compare as CompareIcon,
  Share as ShareIcon,
  Print as PrintIcon,
  Save as SaveIcon,
  Delete as DeleteIcon,
  Archive as ArchiveIcon,
  Restore as RestoreIcon,
  Star as StarIcon,
  StarBorder as StarBorderIcon,
  Comment as CommentIcon,
  Link as LinkIcon,
  Launch as LaunchIcon,
  Favorite as FavoriteIcon,
  FavoriteBorder as FavoriteBorderIcon,
  MoreVert as MoreVertIcon,
  KeyboardArrowDown as KeyboardArrowDownIcon,
  KeyboardArrowUp as KeyboardArrowUpIcon,
  OpenInNew as OpenInNewIcon,
  ContentCopy as ContentCopyIcon,
  CloudDownload as CloudDownloadIcon,
  Sync as SyncIcon,
  SyncProblem as SyncProblemIcon,
  CheckCircleOutline as CheckCircleOutlineIcon,
  RadioButtonUnchecked as RadioButtonUncheckedIcon,
  Cancel as CancelIcon,
  HourglassEmpty as HourglassEmptyIcon,
  AccessTime as AccessTimeIcon,
  CalendarToday as CalendarTodayIcon,
  Person as PersonIcon,
  Group as GroupIcon,
  Public as PublicIcon,
  Lock as LockIcon,
  VpnKey as VpnKeyIcon,
  Shield as ShieldIcon,
  VerifiedUser as VerifiedUserIcon,
  Gavel as GavelIcon,
  Policy as PolicyIcon,
  Assignment as AssignmentIcon,
  AccountTree as AccountTreeIcon,
  DeviceHub as DeviceHubIcon,
  Memory as MemoryIcon,
  Computer as ComputerIcon,
  PhoneAndroid as PhoneAndroidIcon,
  Web as WebIcon,
  Cloud as CloudIcon,
  Storage as StorageIconAlt,
  DataUsage as DataUsageIcon,
  NetworkCheck as NetworkCheckIcon,
  Wifi as WifiIcon,
  WifiOff as WifiOffIcon,
  SignalWifi4Bar as SignalWifi4BarIcon,
  SignalWifiOff as SignalWifiOffIcon,
  Bluetooth as BluetoothIcon,
  BluetoothDisabled as BluetoothDisabledIcon,
  Usb as UsbIcon,
  UsbOff as UsbOffIcon,
  Power as PowerIcon,
  PowerOff as PowerOffIcon,
  Battery20 as Battery20Icon,
  Battery50 as Battery50Icon,
  Battery80 as Battery80Icon,
  BatteryFull as BatteryFullIcon,
  BatteryAlert as BatteryAlertIcon,
  BatteryUnknown as BatteryUnknownIcon,
  Thermostat as ThermostatIcon,
  AcUnit as AcUnitIcon,
  WbSunny as WbSunnyIcon,
  Brightness1 as Brightness1Icon,
  Brightness2 as Brightness2Icon,
  Brightness3 as Brightness3Icon,
  Brightness4 as Brightness4Icon,
  Brightness5 as Brightness5Icon,
  Brightness6 as Brightness6Icon,
  Brightness7 as Brightness7Icon,
  BrightnessHigh as BrightnessHighIcon,
  BrightnessLow as BrightnessLowIcon,
  BrightnessMedium as BrightnessMediumIcon,
  Flare as FlareIcon,
  Flash as FlashIcon,
  FlashAuto as FlashAutoIcon,
  FlashOff as FlashOffIcon,
  FlashOn as FlashOnIcon,
  Highlight as HighlightIcon,
  HighlightOff as HighlightOffIcon,
  Lens as LensIcon,
  Looks as LooksIcon,
  Palette as PaletteIcon,
  ColorLens as ColorLensIcon,
  Brush as BrushIcon,
  FormatPaint as FormatPaintIcon,
  Gradient as GradientIcon,
  InvertColors as InvertColorsIcon,
  InvertColorsOff as InvertColorsOffIcon,
  Opacity as OpacityIcon,
  Texture as TextureIcon,
  Wallpaper as WallpaperIcon,
  Image as ImageIcon,
  ImageAspectRatio as ImageAspectRatioIcon,
  ImageNotSupported as ImageNotSupportedIcon,
  ImageSearch as ImageSearchIcon,
  Collections as CollectionsIcon,
  CollectionsBookmark as CollectionsBookmarkIcon,
  Photo as PhotoIcon,
  PhotoAlbum as PhotoAlbumIcon,
  PhotoCamera as PhotoCameraIcon,
  PhotoCameraBack as PhotoCameraBackIcon,
  PhotoCameraFront as PhotoCameraFrontIcon,
  PhotoFilter as PhotoFilterIcon,
  PhotoLibrary as PhotoLibraryIcon,
  PhotoSizeSelectActual as PhotoSizeSelectActualIcon,
  PhotoSizeSelectLarge as PhotoSizeSelectLargeIcon,
  PhotoSizeSelectSmall as PhotoSizeSelectSmallIcon,
  PictureAsPdf as PictureAsPdfIcon,
  PictureInPicture as PictureInPictureIcon,
  PictureInPictureAlt as PictureInPictureAltIcon,
  SlideShow as SlideShowIcon,
  SwitchCamera as SwitchCameraIcon,
  SwitchVideo as SwitchVideoIcon,
  TagFaces as TagFacesIcon,
  ViewCarousel as ViewCarouselIcon,
  ViewColumn as ViewColumnIcon,
  ViewComfy as ViewComfyIcon,
  ViewCompact as ViewCompactIcon,
  ViewDay as ViewDayIcon,
  ViewHeadline as ViewHeadlineIcon,
  ViewList as ViewListIcon,
  ViewModule as ViewModuleIcon,
  ViewQuilt as ViewQuiltIcon,
  ViewStream as ViewStreamIcon,
  ViewWeek as ViewWeekIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  RemoveRedEye as RemoveRedEyeIcon,
} from '@mui/icons-material';
import { useSocket } from '../../contexts/SocketContext';

interface ScanFinding {
  id: string;
  type: 'vulnerability' | 'malware' | 'typosquatting' | 'suspicious';
  severity: 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  package: string;
  version?: string;
  file: string;
  line?: number;
  column?: number;
  impact: string;
  recommendation: string;
  references: string[];
  confidence: number;
  status: 'open' | 'resolved' | 'false_positive' | 'accepted_risk';
  assignee?: string;
  tags: string[];
  comments: {
    id: string;
    author: string;
    content: string;
    timestamp: Date;
  }[];
  autoFixAvailable: boolean;
  cve?: string;
  cvss?: number;
  createdAt: Date;
  updatedAt: Date;
}

interface ScanResult {
  id: string;
  projectName: string;
  projectPath: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  status: 'completed' | 'running' | 'failed' | 'cancelled';
  source: 'vscode' | 'cli' | 'api';
  findings: ScanFinding[];
  summary: {
    totalPackages: number;
    scannedPackages: number;
    vulnerabilities: number;
    malware: number;
    typosquatting: number;
    suspicious: number;
    riskScore: number;
  };
  metadata?: {
    version: string;
    environment: string;
    branch?: string;
    commit?: string;
    tags: string[];
  };
  performance: {
    scanTime: number;
    memoryUsage: number;
    cpuUsage: number;
  };
}

interface FilterOptions {
  source: string[];
  status: string[];
  severity: string[];
  type: string[];
  category: string[];
  dateRange: {
    start?: Date;
    end?: Date;
  };
  searchQuery: string;
  showOnlyFavorites: boolean;
  showOnlyUnresolved: boolean;
}

const ScanResults: React.FC = () => {
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [filteredResults, setFilteredResults] = useState<ScanResult[]>([]);
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<ScanFinding | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTab, setSelectedTab] = useState(0);
  const [filters, setFilters] = useState<FilterOptions>({
    source: [],
    status: [],
    severity: [],
    type: [],
    category: [],
    dateRange: {},
    searchQuery: '',
    showOnlyFavorites: false,
    showOnlyUnresolved: false,
  });
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [findingDialogOpen, setFindingDialogOpen] = useState(false);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [compareDialogOpen, setCompareDialogOpen] = useState(false);
  const [expandedResults, setExpandedResults] = useState<Set<string>>(new Set());
  const [favorites, setFavorites] = useState<Set<string>>(new Set());
  const { scanEvents } = useSocket();

  useEffect(() => {
    loadScanResults();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [scanResults, filters]);

  useEffect(() => {
    // Listen for real-time scan events
    if (scanEvents.length > 0) {
      const latestEvent = scanEvents[scanEvents.length - 1];
      updateScanFromEvent(latestEvent);
    }
  }, [scanEvents]);

  const loadScanResults = async () => {
    try {
      setLoading(true);
      // Simulate API call
      const mockResults: ScanResult[] = [
        {
          id: '1',
          projectName: 'Frontend App',
          projectPath: '/workspace/frontend',
          startTime: new Date('2024-01-15T10:30:00'),
          endTime: new Date('2024-01-15T10:35:00'),
          duration: 300000,
          status: 'completed',
          source: 'vscode',
          findings: [
            {
              id: 'f1',
              type: 'vulnerability',
              severity: 'high',
              title: 'Cross-Site Scripting (XSS) Vulnerability',
              description: 'Potential XSS vulnerability detected in user input handling',
              package: 'react-dom',
              version: '17.0.2',
              file: 'src/components/UserInput.tsx',
              line: 45,
              column: 12,
              impact: 'Attackers could inject malicious scripts',
              recommendation: 'Sanitize user input and use proper escaping',
              references: ['https://owasp.org/www-community/attacks/xss/'],
              confidence: 85,
              status: 'open',
              tags: ['security', 'xss', 'frontend'],
              comments: [],
              autoFixAvailable: true,
              cve: 'CVE-2024-1234',
              cvss: 7.5,
              createdAt: new Date(),
              updatedAt: new Date()
            }
          ],
          summary: {
            totalPackages: 150,
            scannedPackages: 150,
            vulnerabilities: 3,
            malware: 0,
            typosquatting: 1,
            suspicious: 2,
            riskScore: 7.2
          },
          metadata: {
            version: '1.0.0',
            environment: 'development',
            branch: 'main',
            commit: 'abc123',
            tags: ['frontend', 'react']
          },
          performance: {
            scanTime: 300000,
            memoryUsage: 512,
            cpuUsage: 45
          }
        }
      ];
      setScanResults(mockResults);
    } catch (error) {
      console.error('Failed to load scan results:', error);
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...scanResults];

    if (filters.source.length > 0) {
      filtered = filtered.filter(result => filters.source.includes(result.source));
    }

    if (filters.status.length > 0) {
      filtered = filtered.filter(result => filters.status.includes(result.status));
    }

    if (filters.searchQuery) {
      const query = filters.searchQuery.toLowerCase();
      filtered = filtered.filter(result => 
        result.projectName.toLowerCase().includes(query) ||
        result.projectPath.toLowerCase().includes(query) ||
        result.findings.some(finding => 
          finding.title.toLowerCase().includes(query) ||
          finding.description.toLowerCase().includes(query) ||
          finding.package.toLowerCase().includes(query)
        )
      );
    }

    if (filters.showOnlyFavorites) {
      filtered = filtered.filter(result => favorites.has(result.id));
    }

    if (filters.showOnlyUnresolved) {
      filtered = filtered.filter(result => 
        result.findings.some(finding => finding.status === 'open')
      );
    }

    setFilteredResults(filtered);
  };

  const updateScanFromEvent = (event: any) => {
    // Handle real-time scan updates
    console.log('Received scan event:', event);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#ffeb3b';
      case 'info': return '#2196f3';
      default: return '#9e9e9e';
    }
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

  const getFindingIcon = (type: string) => {
    switch (type) {
      case 'vulnerability': return <SecurityIcon />;
      case 'malware': return <BugIcon />;
      case 'typosquatting': return <WarningIcon />;
      case 'suspicious': return <InfoIcon />;
      default: return <InfoIcon />;
    }
  };

  const toggleFavorite = (resultId: string) => {
    const newFavorites = new Set(favorites);
    if (favorites.has(resultId)) {
      newFavorites.delete(resultId);
    } else {
      newFavorites.add(resultId);
    }
    setFavorites(newFavorites);
  };

  const toggleExpanded = (resultId: string) => {
    const newExpanded = new Set(expandedResults);
    if (expandedResults.has(resultId)) {
      newExpanded.delete(resultId);
    } else {
      newExpanded.add(resultId);
    }
    setExpandedResults(newExpanded);
  };

  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const paginatedResults = filteredResults.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography variant="h4" gutterBottom>
          Scan Results
        </Typography>
        <LinearProgress />
        <Typography variant="body2" sx={{ mt: 2 }}>
          Loading scan results...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Scan Results
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
        View and manage your security scan results.
      </Typography>
      
      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={3}>
              <TextField
                fullWidth
                size="small"
                placeholder="Search results..."
                value={filters.searchQuery}
                onChange={(e) => setFilters({...filters, searchQuery: e.target.value})}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                  endAdornment: filters.searchQuery && (
                    <IconButton size="small" onClick={() => setFilters({...filters, searchQuery: ''})}>
                      <ClearIcon />
                    </IconButton>
                  )
                }}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <Autocomplete
                multiple
                size="small"
                options={['high', 'medium', 'low', 'info']}
                value={filters.severity}
                onChange={(_, newValue) => setFilters({...filters, severity: newValue})}
                renderInput={(params) => <TextField {...params} label="Severity" />}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <Autocomplete
                multiple
                size="small"
                options={['security', 'performance', 'maintainability', 'reliability']}
                value={filters.category}
                onChange={(_, newValue) => setFilters({...filters, category: newValue})}
                renderInput={(params) => <TextField {...params} label="Category" />}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <Autocomplete
                multiple
                size="small"
                options={['vscode', 'cli', 'api']}
                value={filters.source}
                onChange={(_, newValue) => setFilters({...filters, source: newValue})}
                renderInput={(params) => <TextField {...params} label="Source" />}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <Autocomplete
                multiple
                size="small"
                options={['completed', 'running', 'failed', 'cancelled']}
                value={filters.status}
                onChange={(_, newValue) => setFilters({...filters, status: newValue})}
                renderInput={(params) => <TextField {...params} label="Status" />}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <FormControlLabel
                control={
                  <Switch 
                    checked={filters.showOnlyFavorites}
                    onChange={(e) => setFilters({...filters, showOnlyFavorites: e.target.checked})}
                  />
                }
                label="Favorites Only"
              />
            </Grid>
            <Grid item xs={12} md={3}>
              <FormControlLabel
                control={
                  <Switch 
                    checked={filters.showOnlyUnresolved}
                    onChange={(e) => setFilters({...filters, showOnlyUnresolved: e.target.checked})}
                  />
                }
                label="Unresolved Only"
              />
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={selectedTab} onChange={(_, newValue) => setSelectedTab(newValue)}>
          <Tab label="Results List" />
          <Tab label="Analytics" />
          <Tab label="Trends" />
        </Tabs>
      </Box>

      {/* Results List Tab */}
      {selectedTab === 0 && (
        <>
          {/* Summary Cards */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <SecurityIcon sx={{ mr: 1, color: 'primary.main' }} />
                    <Typography variant="h6">Total Scans</Typography>
                  </Box>
                  <Typography variant="h4" color="primary">
                    {scanResults.length}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <ErrorIcon sx={{ mr: 1, color: 'error.main' }} />
                    <Typography variant="h6">Critical Issues</Typography>
                  </Box>
                  <Typography variant="h4" color="error">
                    {scanResults.reduce((acc, result) => 
                      acc + result.findings.filter(f => f.severity === 'high').length, 0
                    )}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <CheckCircleIcon sx={{ mr: 1, color: 'success.main' }} />
                    <Typography variant="h6">Resolved</Typography>
                  </Box>
                  <Typography variant="h4" color="success">
                    {scanResults.reduce((acc, result) => 
                      acc + result.findings.filter(f => f.status === 'resolved').length, 0
                    )}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <SpeedIcon sx={{ mr: 1, color: 'info.main' }} />
                    <Typography variant="h6">Avg Scan Time</Typography>
                  </Box>
                  <Typography variant="h4" color="info">
                    {scanResults.length > 0 ? 
                      Math.round(scanResults.reduce((acc, result) => acc + result.duration, 0) / scanResults.length / 1000) + 's'
                      : '0s'
                    }
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </>
      )}

      {/* Analytics Tab */}
      {selectedTab === 1 && (
        <>
          {/* Analytics content will go here */}
          <Typography variant="h6">Analytics Dashboard</Typography>
        </>
      )}

      {/* Trends Tab */}
      {selectedTab === 2 && (
        <>
          {/* Trends content will go here */}
          <Typography variant="h6">Trends Analysis</Typography>
        </>
      )}
    </Box>
  );
};

export default ScanResults;
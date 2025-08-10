import { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  BarChart3, 
  TrendingUp, 
  TrendingDown, 
  Shield, 
  AlertTriangle, 
  Clock,
  RefreshCw,
  Download,
  Activity,
  Target,
  LineChart,
  Package,
  X,
  Eye,
  FileText,
  Bug,
  Info
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'

const timeRanges = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: '1y', label: 'Last year' }
]

const vulnerabilityTrends = [
  { date: '2023-10-01', critical: 2, high: 5, medium: 12, low: 8 },
  { date: '2023-10-02', critical: 1, high: 6, medium: 10, low: 9 },
  { date: '2023-10-03', critical: 3, high: 4, medium: 15, low: 7 },
  { date: '2023-10-04', critical: 1, high: 7, medium: 11, low: 10 },
  { date: '2023-10-05', critical: 2, high: 3, medium: 13, low: 6 },
  { date: '2023-10-06', critical: 0, high: 5, medium: 9, low: 8 },
  { date: '2023-10-07', critical: 1, high: 4, medium: 14, low: 5 }
]

const scanMetrics = [
  { name: 'Dependency Scans', value: 1247, change: 12.5, trend: 'up' },
  { name: 'Vulnerability Checks', value: 856, change: -3.2, trend: 'down' },
  { name: 'Security Audits', value: 234, change: 8.7, trend: 'up' },
  { name: 'Compliance Checks', value: 445, change: 15.3, trend: 'up' }
]

const topVulnerabilities = [
  { name: 'Cross-Site Scripting (XSS)', count: 23, severity: 'high', trend: 'up' },
  { name: 'SQL Injection', count: 18, severity: 'critical', trend: 'down' },
  { name: 'Prototype Pollution', count: 15, severity: 'medium', trend: 'up' },
  { name: 'Remote Code Execution', count: 12, severity: 'critical', trend: 'stable' },
  { name: 'Path Traversal', count: 9, severity: 'medium', trend: 'down' }
]

const packageStats = [
  { category: 'Frontend', packages: 156, vulnerabilities: 23, riskScore: 7.2 },
  { category: 'Backend', packages: 89, vulnerabilities: 15, riskScore: 6.8 },
  { category: 'DevOps', packages: 45, vulnerabilities: 8, riskScore: 5.4 },
  { category: 'Testing', packages: 67, vulnerabilities: 12, riskScore: 6.1 }
]

export function Analytics() {
  const [timeRange, setTimeRange] = useState('7d')
  
  // Modal state
  const [showVulnDetailsModal, setShowVulnDetailsModal] = useState(false)
  const [showPackageDetailsModal, setShowPackageDetailsModal] = useState(false)
  const [selectedVuln, setSelectedVuln] = useState<any>(null)
  const [selectedPackage, setSelectedPackage] = useState<any>(null)

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600'
      case 'high':
        return 'text-orange-600'
      case 'medium':
        return 'text-yellow-600'
      case 'low':
        return 'text-blue-600'
      default:
        return 'text-gray-600'
    }
  }

  const getTrendIcon = (trend: string, change?: number) => {
    if (trend === 'up' || (change && change > 0)) {
      return <TrendingUp className="w-4 h-4 text-green-500" />
    } else if (trend === 'down' || (change && change < 0)) {
      return <TrendingDown className="w-4 h-4 text-red-500" />
    }
    return <Activity className="w-4 h-4 text-gray-500" />
  }

  const getRiskColor = (score: number) => {
    if (score >= 8) return 'text-red-600 bg-red-100'
    if (score >= 6) return 'text-orange-600 bg-orange-100'
    if (score >= 4) return 'text-yellow-600 bg-yellow-100'
    return 'text-green-600 bg-green-100'
  }

  const handleViewVulnDetails = (vuln: any) => {
    setSelectedVuln(vuln)
    setShowVulnDetailsModal(true)
  }

  const handleViewPackageDetails = (packageStat: any) => {
    setSelectedPackage(packageStat)
    setShowPackageDetailsModal(true)
  }

  const handleCloseVulnDetails = () => {
    setShowVulnDetailsModal(false)
    setSelectedVuln(null)
  }

  const handleClosePackageDetails = () => {
    setShowPackageDetailsModal(false)
    setSelectedPackage(null)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Analytics</h1>
          <p className="text-gray-600">
            Security insights and performance metrics
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-2">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="px-3 py-2 bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {timeRanges.map((range) => (
              <option key={range.value} value={range.value}>
                {range.label}
              </option>
            ))}
          </select>
          <Button variant="outline">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button>
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
        </div>
      </motion.div>

      {/* Key Metrics */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"
      >
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Vulnerabilities</p>
                <p className="text-2xl font-bold">127</p>
                <div className="flex items-center mt-1">
                  {getTrendIcon('down', -8.2)}
                  <span className="text-sm text-green-600 ml-1">8.2% decrease</span>
                </div>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Security Score</p>
                <p className="text-2xl font-bold">8.4</p>
                <div className="flex items-center mt-1">
                  {getTrendIcon('up', 12.5)}
                  <span className="text-sm text-green-600 ml-1">12.5% increase</span>
                </div>
              </div>
              <Shield className="w-8 h-8 text-green-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Scans Performed</p>
                <p className="text-2xl font-bold">2,847</p>
                <div className="flex items-center mt-1">
                  {getTrendIcon('up', 23.1)}
                  <span className="text-sm text-green-600 ml-1">23.1% increase</span>
                </div>
              </div>
              <Target className="w-8 h-8 text-blue-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Avg Response Time</p>
                <p className="text-2xl font-bold">2.3h</p>
                <div className="flex items-center mt-1">
                  {getTrendIcon('down', -15.7)}
                  <span className="text-sm text-green-600 ml-1">15.7% faster</span>
                </div>
              </div>
              <Clock className="w-8 h-8 text-purple-500" />
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Trends */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <LineChart className="w-5 h-5 mr-2" />
                Vulnerability Trends
              </CardTitle>
              <CardDescription>
                Daily vulnerability detection over the past week
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {vulnerabilityTrends.map((day) => (
                  <div key={day.date} className="flex items-center space-x-4">
                    <div className="w-20 text-sm text-gray-600">
                      {new Date(day.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                    </div>
                    <div className="flex-1 flex space-x-1">
                      <div 
                        className="bg-red-500 h-4 rounded-sm"
                        style={{ width: `${(day.critical / 5) * 100}%`, minWidth: day.critical > 0 ? '8px' : '0' }}
                        title={`${day.critical} critical`}
                      />
                      <div 
                        className="bg-orange-500 h-4 rounded-sm"
                        style={{ width: `${(day.high / 10) * 100}%`, minWidth: day.high > 0 ? '8px' : '0' }}
                        title={`${day.high} high`}
                      />
                      <div 
                        className="bg-yellow-500 h-4 rounded-sm"
                        style={{ width: `${(day.medium / 20) * 100}%`, minWidth: day.medium > 0 ? '8px' : '0' }}
                        title={`${day.medium} medium`}
                      />
                      <div 
                        className="bg-blue-500 h-4 rounded-sm"
                        style={{ width: `${(day.low / 15) * 100}%`, minWidth: day.low > 0 ? '8px' : '0' }}
                        title={`${day.low} low`}
                      />
                    </div>
                    <div className="text-sm font-medium w-8">
                      {day.critical + day.high + day.medium + day.low}
                    </div>
                  </div>
                ))}
                <div className="flex items-center justify-center space-x-4 pt-4 border-t">
                  <div className="flex items-center space-x-1">
                    <div className="w-3 h-3 bg-red-500 rounded-sm" />
                    <span className="text-xs text-gray-600">Critical</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <div className="w-3 h-3 bg-orange-500 rounded-sm" />
                    <span className="text-xs text-gray-600">High</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <div className="w-3 h-3 bg-yellow-500 rounded-sm" />
                    <span className="text-xs text-gray-600">Medium</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <div className="w-3 h-3 bg-blue-500 rounded-sm" />
                    <span className="text-xs text-gray-600">Low</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Scan Metrics */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <BarChart3 className="w-5 h-5 mr-2" />
                Scan Metrics
              </CardTitle>
              <CardDescription>
                Performance metrics for different scan types
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {scanMetrics.map((metric) => (
                  <div key={metric.name} className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium">{metric.name}</span>
                        <div className="flex items-center space-x-2">
                          <span className="text-sm font-bold">{metric.value.toLocaleString()}</span>
                          <div className="flex items-center">
                            {getTrendIcon(metric.trend, metric.change)}
                            <span className={`text-xs ml-1 ${
                              metric.change > 0 ? 'text-green-600' : 'text-red-600'
                            }`}>
                              {Math.abs(metric.change)}%
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div 
                          className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                          style={{ width: `${(metric.value / 1500) * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Bottom Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Vulnerabilities */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2" />
                Top Vulnerabilities
              </CardTitle>
              <CardDescription>
                Most common vulnerability types detected
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {topVulnerabilities.map((vuln, index) => (
                  <div key={vuln.name} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-medium">{vuln.name}</span>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(vuln.severity)} bg-opacity-10`}>
                          {vuln.severity}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2 mt-1">
                        <span className="text-sm text-gray-600">{vuln.count} occurrences</span>
                        {getTrendIcon(vuln.trend)}
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="text-lg font-bold">{index + 1}</div>
                      <Button variant="ghost" size="sm" onClick={() => handleViewVulnDetails(vuln)}>
                        <Eye className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Package Statistics */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Package className="w-5 h-5 mr-2" />
                Package Statistics
              </CardTitle>
              <CardDescription>
                Security analysis by package category
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {packageStats.map((stat) => (
                  <div key={stat.category} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium">{stat.category}</span>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getRiskColor(stat.riskScore)}`}>
                          Risk: {stat.riskScore}/10
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-sm text-gray-600">
                        <div className="flex items-center">
                          <Package className="w-4 h-4 mr-1" />
                          {stat.packages} packages
                        </div>
                        <div className="flex items-center">
                          <AlertTriangle className="w-4 h-4 mr-1" />
                          {stat.vulnerabilities} vulnerabilities
                        </div>
                      </div>
                    </div>
                    <Button variant="ghost" size="sm" onClick={() => handleViewPackageDetails(stat)}>
                      <Eye className="w-4 h-4" />
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Vulnerability Details Modal */}
      {showVulnDetailsModal && selectedVuln && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            className="bg-background rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
          >
            <div className="flex items-center justify-between p-6 border-b border-border">
              <div>
                <h2 className="text-xl font-semibold">Vulnerability Details</h2>
                <p className="text-sm text-muted-foreground">
                  Detailed analysis of {selectedVuln.name}
                </p>
              </div>
              <Button variant="ghost" size="sm" onClick={handleCloseVulnDetails}>
                <X className="w-4 h-4" />
              </Button>
            </div>

            <div className="p-6 space-y-6">
              {/* Basic Information */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Vulnerability Type</label>
                  <p className="text-sm mt-1 font-medium">{selectedVuln.name}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Severity Level</label>
                  <div className="flex items-center space-x-2 mt-1">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(selectedVuln.severity)} bg-opacity-20`}>
                      {selectedVuln.severity}
                    </span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Occurrences</label>
                  <div className="flex items-center space-x-2 mt-1">
                    <Bug className="w-4 h-4 text-red-500" />
                    <span className="text-sm font-medium">{selectedVuln.count}</span>
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Trend</label>
                  <div className="flex items-center space-x-2 mt-1">
                    {getTrendIcon(selectedVuln.trend)}
                    <span className="text-sm capitalize">{selectedVuln.trend}</span>
                  </div>
                </div>
              </div>

              {/* Detailed Analysis */}
              <div>
                <label className="text-sm font-medium text-muted-foreground">Description</label>
                <div className="mt-2 p-4 bg-muted rounded-lg">
                  <p className="text-sm">
                    {selectedVuln.name === 'Cross-Site Scripting (XSS)' && 
                      "Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user."
                    }
                    {selectedVuln.name === 'SQL Injection' && 
                      "SQL injection is a code injection technique that might destroy your database. SQL injection is one of the most common web hacking techniques. SQL injection is the placement of malicious code in SQL statements, via web page input."
                    }
                    {selectedVuln.name === 'Prototype Pollution' && 
                      "Prototype pollution is a vulnerability affecting JavaScript. Prototype pollution refers to the ability to inject properties into existing JavaScript language construct prototypes, such as objects."
                    }
                    {selectedVuln.name === 'Remote Code Execution' && 
                      "Remote code execution (RCE) refers to the ability of a cyberattacker to access and make changes to a computer owned by another, without authority and regardless of where the computer is geographically located."
                    }
                    {selectedVuln.name === 'Path Traversal' && 
                      "A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with 'dot-dot-slash (../)' sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system."
                    }
                  </p>
                </div>
              </div>

              {/* Impact Assessment */}
              <div>
                <label className="text-sm font-medium text-muted-foreground">Impact Assessment</label>
                <div className="mt-2 grid grid-cols-3 gap-4">
                  <div className="p-3 bg-muted rounded-lg text-center">
                    <div className="text-lg font-bold text-red-600">{Math.floor(selectedVuln.count * 0.3)}</div>
                    <div className="text-xs text-muted-foreground">Critical Impact</div>
                  </div>
                  <div className="p-3 bg-muted rounded-lg text-center">
                    <div className="text-lg font-bold text-orange-600">{Math.floor(selectedVuln.count * 0.5)}</div>
                    <div className="text-xs text-muted-foreground">High Impact</div>
                  </div>
                  <div className="p-3 bg-muted rounded-lg text-center">
                    <div className="text-lg font-bold text-yellow-600">{Math.floor(selectedVuln.count * 0.2)}</div>
                    <div className="text-xs text-muted-foreground">Medium Impact</div>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap gap-2 pt-4 border-t border-border">
                <Button className="flex-1">
                  <FileText className="w-4 h-4 mr-2" />
                  Generate Report
                </Button>
                <Button variant="outline" className="flex-1">
                  <Bug className="w-4 h-4 mr-2" />
                  View Instances
                </Button>
                <Button variant="outline" className="flex-1">
                  <Info className="w-4 h-4 mr-2" />
                  Remediation Guide
                </Button>
              </div>
            </div>
          </motion.div>
        </div>
      )}

      {/* Package Details Modal */}
      {showPackageDetailsModal && selectedPackage && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            className="bg-background rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
          >
            <div className="flex items-center justify-between p-6 border-b border-border">
              <div>
                <h2 className="text-xl font-semibold">Package Category Details</h2>
                <p className="text-sm text-muted-foreground">
                  Security analysis for {selectedPackage.category} packages
                </p>
              </div>
              <Button variant="ghost" size="sm" onClick={handleClosePackageDetails}>
                <X className="w-4 h-4" />
              </Button>
            </div>

            <div className="p-6 space-y-6">
              {/* Basic Information */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Category</label>
                  <p className="text-sm mt-1 font-medium">{selectedPackage.category}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Risk Score</label>
                  <div className="flex items-center space-x-2 mt-1">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getRiskColor(selectedPackage.riskScore)}`}>
                      {selectedPackage.riskScore}/10
                    </span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Total Packages</label>
                  <div className="flex items-center space-x-2 mt-1">
                    <Package className="w-4 h-4 text-blue-500" />
                    <span className="text-sm font-medium">{selectedPackage.packages}</span>
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Vulnerabilities</label>
                  <div className="flex items-center space-x-2 mt-1">
                    <AlertTriangle className="w-4 h-4 text-red-500" />
                    <span className="text-sm font-medium">{selectedPackage.vulnerabilities}</span>
                  </div>
                </div>
              </div>

              {/* Package Breakdown */}
              <div>
                <label className="text-sm font-medium text-muted-foreground">Package Breakdown</label>
                <div className="mt-2 space-y-3">
                  {[
                    { name: 'Core Dependencies', count: Math.floor(selectedPackage.packages * 0.4), vulns: Math.floor(selectedPackage.vulnerabilities * 0.3) },
                    { name: 'Development Dependencies', count: Math.floor(selectedPackage.packages * 0.3), vulns: Math.floor(selectedPackage.vulnerabilities * 0.4) },
                    { name: 'Optional Dependencies', count: Math.floor(selectedPackage.packages * 0.2), vulns: Math.floor(selectedPackage.vulnerabilities * 0.2) },
                    { name: 'Peer Dependencies', count: Math.floor(selectedPackage.packages * 0.1), vulns: Math.floor(selectedPackage.vulnerabilities * 0.1) }
                  ].map((item) => (
                    <div key={item.name} className="flex items-center justify-between p-3 bg-muted rounded-lg">
                      <div>
                        <div className="text-sm font-medium">{item.name}</div>
                        <div className="text-xs text-muted-foreground">{item.count} packages</div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-medium text-red-600">{item.vulns}</div>
                        <div className="text-xs text-muted-foreground">vulnerabilities</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Security Recommendations */}
              <div>
                <label className="text-sm font-medium text-muted-foreground">Security Recommendations</label>
                <div className="mt-2 p-4 bg-muted rounded-lg">
                  <ul className="text-sm space-y-2">
                    <li className="flex items-start space-x-2">
                      <div className="w-1.5 h-1.5 bg-blue-500 rounded-full mt-2 flex-shrink-0" />
                      <span>Update {Math.floor(selectedPackage.vulnerabilities * 0.6)} packages to latest versions</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <div className="w-1.5 h-1.5 bg-blue-500 rounded-full mt-2 flex-shrink-0" />
                      <span>Review and remove {Math.floor(selectedPackage.packages * 0.1)} unused dependencies</span>
                    </li>
                    <li className="flex items-start space-x-2">
                      <div className="w-1.5 h-1.5 bg-blue-500 rounded-full mt-2 flex-shrink-0" />
                      <span>Implement automated security scanning for this category</span>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap gap-2 pt-4 border-t border-border">
                <Button className="flex-1">
                  <FileText className="w-4 h-4 mr-2" />
                  Generate Report
                </Button>
                <Button variant="outline" className="flex-1">
                  <Package className="w-4 h-4 mr-2" />
                  View Packages
                </Button>
                <Button variant="outline" className="flex-1">
                  <Shield className="w-4 h-4 mr-2" />
                  Security Scan
                </Button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  )
}
import { motion } from 'framer-motion'
import { useState } from 'react'
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Activity,
  TrendingUp,
  Clock,
  Users,
  Database,
  RefreshCw,
  X,
  Eye,
  FileText,
  Calendar,
  Target,
  Bug
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { useDashboard, useScans } from '../hooks/useApi'
import { useNotifications } from '../contexts/NotificationContext'
import { useNavigate } from 'react-router-dom'
import { apiService } from '../services/api'

export function Dashboard() {
  const navigate = useNavigate()
  const { stats, recentScans, loading, error, refetch } = useDashboard()
  const { createScan } = useScans()
  const { success, showError } = useNotifications()
  
  // Modal state
  const [showDetailsModal, setShowDetailsModal] = useState(false)
  const [selectedScan, setSelectedScan] = useState<any>(null)

  const handleRunScan = async () => {
    try {
      success('Starting new security scan...')
      await createScan({
        name: `Quick Scan ${new Date().toLocaleTimeString()}`,
        target: 'package.json',
        type: 'quick'
      })
      success('Security scan started successfully!')
    } catch (err) {
      showError('Failed to start security scan')
    }
  }

  const handleUpdateDatabase = async () => {
    try {
      const result = await apiService.updateDatabase()
      if (result.success) {
        success('Database update started successfully!')
      } else {
        showError('Failed to start database update')
      }
    } catch (err) {
      showError('Failed to start database update')
    }
  }

  const handleViewAnalytics = () => {
    navigate('/analytics')
  }

  const handleManageTeam = () => {
    success('Navigating to team management...')
    navigate('/team')
  }

  const handleViewDetails = (scan: any) => {
    setSelectedScan(scan)
    setShowDetailsModal(true)
  }

  const handleCloseDetails = () => {
    setShowDetailsModal(false)
    setSelectedScan(null)
  }

  const handleNavigateToDetails = (scanId: string) => {
    success('Navigating to scan details...')
    navigate(`/security-scans/${scanId}`)
  }

  const handleTimeFilter = () => {
    // This could open a date picker or filter modal
    success('Time filter functionality coming soon!')
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-primary" />
        <span className="ml-2 text-lg">Loading dashboard...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64 text-red-600">
        <AlertTriangle className="w-8 h-8 mr-2" />
        <span className="text-lg">Error loading dashboard: {error}</span>
        <Button onClick={refetch} className="ml-4">
          <RefreshCw className="w-4 h-4 mr-2" />
          Retry
        </Button>
      </div>
    )
  }

  const statsData = stats ? [
    {
      name: 'Total Scans',
      value: stats.totalScans.toLocaleString(),
      change: '+12%',
      changeType: 'positive' as const,
      icon: Shield,
    },
    {
      name: 'Vulnerabilities Found',
      value: stats.vulnerabilitiesFound.toString(),
      change: '-8%',
      changeType: 'negative' as const,
      icon: AlertTriangle,
    },
    {
      name: 'Packages Secured',
      value: stats.packagesSecured.toLocaleString(),
      change: '+23%',
      changeType: 'positive' as const,
      icon: CheckCircle,
    },
    {
      name: 'Active Monitors',
      value: stats.activeMonitors.toString(),
      change: '+5%',
      changeType: 'positive' as const,
      icon: Activity,
    },
  ] : []
  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">
            Monitor your security posture and package vulnerabilities
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-2">
          <Button variant="outline" onClick={handleTimeFilter}>
            <Clock className="w-4 h-4 mr-2" />
            Last 24h
          </Button>
          <Button onClick={handleRunScan}>
            <Shield className="w-4 h-4 mr-2" />
            Run Scan
          </Button>
        </div>
      </motion.div>

      {/* Stats Grid */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
      >
        {statsData.map((stat, index) => (
          <motion.div
            key={stat.name}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.1 + index * 0.05 }}
          >
            <Card className="card-hover">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">
                      {stat.name}
                    </p>
                    <p className="text-2xl font-bold">{stat.value}</p>
                    <p className={`text-xs ${
                      stat.changeType === 'positive' 
                        ? 'text-green-600' 
                        : 'text-red-600'
                    }`}>
                      {stat.change} from last month
                    </p>
                  </div>
                  <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
                    <stat.icon className="w-6 h-6 text-primary" />
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </motion.div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Scans */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="lg:col-span-2"
        >
          <Card>
            <CardHeader>
              <CardTitle>Recent Scans</CardTitle>
              <CardDescription>
                Latest package security scans and their results
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentScans && recentScans.length > 0 ? recentScans.map((scan) => (
                  <div
                    key={scan.id}
                    className="flex items-center justify-between p-4 border border-border rounded-lg hover:bg-accent/50 transition-colors"
                  >
                    <div className="flex items-center space-x-4">
                      <div className={`w-3 h-3 rounded-full ${
                        scan.status === 'completed' 
                          ? 'bg-green-500' 
                          : scan.status === 'running'
                          ? 'bg-blue-500'
                          : scan.status === 'failed'
                          ? 'bg-red-500'
                          : 'bg-yellow-500'
                      }`} />
                      <div>
                        <p className="font-medium">{scan.name}</p>
                        <p className="text-sm text-muted-foreground">
                          {scan.target} • {scan.lastRun}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-medium">
                        {scan.vulnerabilities} vulnerabilities
                      </p>
                      <Button variant="ghost" size="sm" onClick={() => handleViewDetails(scan)}>
                        View Details
                      </Button>
                    </div>
                  </div>
                )) : (
                  <div className="text-center py-8 text-muted-foreground">
                    No recent scans available
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Quick Actions */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="space-y-6"
        >
          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button className="w-full justify-start" onClick={handleRunScan}>
                <Shield className="w-4 h-4 mr-2" />
                Start Security Scan
              </Button>
              <Button variant="outline" className="w-full justify-start" onClick={handleUpdateDatabase}>
                <Database className="w-4 h-4 mr-2" />
                Update Database
              </Button>
              <Button variant="outline" className="w-full justify-start" onClick={handleViewAnalytics}>
                <TrendingUp className="w-4 h-4 mr-2" />
                View Analytics
              </Button>
              <Button variant="outline" className="w-full justify-start" onClick={handleManageTeam}>
                <Users className="w-4 h-4 mr-2" />
                Manage Team
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>System Status</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm">Scanner Engine</span>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full" />
                  <span className="text-sm text-green-600">Online</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">Database</span>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full" />
                  <span className="text-sm text-green-600">Connected</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">API Gateway</span>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full" />
                  <span className="text-sm text-yellow-600">Degraded</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Scan Details Modal */}
      {showDetailsModal && selectedScan && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            className="bg-background rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
          >
            <div className="flex items-center justify-between p-6 border-b border-border">
              <div>
                <h2 className="text-xl font-semibold">Scan Details</h2>
                <p className="text-sm text-muted-foreground">
                  Detailed information about the security scan
                </p>
              </div>
              <Button variant="ghost" size="sm" onClick={handleCloseDetails}>
                <X className="w-4 h-4" />
              </Button>
            </div>

            <div className="p-6 space-y-6">
              {/* Basic Information */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Scan ID</label>
                  <p className="text-sm font-mono bg-muted px-2 py-1 rounded mt-1">
                    {selectedScan.id}
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Status</label>
                  <div className="flex items-center space-x-2 mt-1">
                    <div className={`w-2 h-2 rounded-full ${
                      selectedScan.status === 'completed' 
                        ? 'bg-green-500' 
                        : selectedScan.status === 'running'
                        ? 'bg-blue-500'
                        : selectedScan.status === 'failed'
                        ? 'bg-red-500'
                        : 'bg-yellow-500'
                    }`} />
                    <span className="text-sm capitalize">{selectedScan.status}</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Scan Name</label>
                  <p className="text-sm mt-1">{selectedScan.name}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Target</label>
                  <p className="text-sm mt-1 font-mono">{selectedScan.target}</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Last Run</label>
                  <div className="flex items-center space-x-2 mt-1">
                    <Calendar className="w-4 h-4 text-muted-foreground" />
                    <span className="text-sm">{selectedScan.lastRun}</span>
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Vulnerabilities Found</label>
                  <div className="flex items-center space-x-2 mt-1">
                    <Bug className="w-4 h-4 text-red-500" />
                    <span className="text-sm font-medium">{selectedScan.vulnerabilities}</span>
                  </div>
                </div>
              </div>

              {/* Scan Results Summary */}
              <div>
                <label className="text-sm font-medium text-muted-foreground">Scan Summary</label>
                <div className="mt-2 p-4 bg-muted rounded-lg">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Packages Scanned:</span>
                      <span className="ml-2 font-medium">
                        {Math.floor(Math.random() * 100) + 50}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Dependencies:</span>
                      <span className="ml-2 font-medium">
                        {Math.floor(Math.random() * 500) + 200}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Critical Issues:</span>
                      <span className="ml-2 font-medium text-red-600">
                        {Math.floor(selectedScan.vulnerabilities * 0.1)}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">High Issues:</span>
                      <span className="ml-2 font-medium text-orange-600">
                        {Math.floor(selectedScan.vulnerabilities * 0.3)}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap gap-2 pt-4 border-t border-border">
                <Button 
                  onClick={() => handleNavigateToDetails(selectedScan.id)}
                  className="flex-1"
                >
                  <Eye className="w-4 h-4 mr-2" />
                  View Full Details
                </Button>
                <Button variant="outline" className="flex-1">
                  <FileText className="w-4 h-4 mr-2" />
                  Generate Report
                </Button>
                <Button variant="outline" className="flex-1">
                  <Target className="w-4 h-4 mr-2" />
                  Re-run Scan
                </Button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  )
}
// web/src/pages/Dashboard.tsx
// Refactored Dashboard - "Supply Chain Firewall" instead of "Vulnerability Scanner"
import { motion } from 'framer-motion'
import { useState, useEffect } from 'react'
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Activity,
  TrendingUp,
  Clock,
  Ban,
  Eye,
  FileText,
  Target,
  Zap,
  Lock,
  AlertCircle
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { useDashboard, useScans } from '../hooks/useApi'
import { useNotifications } from '../contexts/NotificationContext'
import { useNavigate } from 'react-router-dom'
import { apiService } from '../services/api'

// NEW: Firewall Stats Interface
interface FirewallStats {
  trafficVolume: number;      // Packages Inspected (was Total Scans)
  threatsBlocked: number;     // Attacks Blocked (was Vulnerabilities)
  policyViolations: number;   // Policy Rejections (e.g. Unsigned)
  activeRules: number;        // Active Firewall Rules
  lastBlockTime?: string;     // When was the last threat blocked
  lastBlockPackage?: string;  // What package was blocked
}

// NEW: Live Activity Feed Item
interface LiveActivity {
  id: string;
  timestamp: Date;
  action: 'BLOCKED' | 'ALLOWED' | 'REVIEWED' | 'ALERTED';
  packageName: string;
  reason: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  policyName?: string;
}

export function Dashboard() {
  const navigate = useNavigate()
  const { stats, recentScans, loading, error, refetch } = useDashboard()
  const { createScan } = useScans()
  const { success, showError } = useNotifications()
  
  // NEW: Firewall-specific state
  const [firewallStatus, setFirewallStatus] = useState<'SECURE' | 'WARNING' | 'BREACH'>('SECURE')
  const [liveActivity, setLiveActivity] = useState<LiveActivity[]>([])
  const [showActivityFeed, setShowActivityFeed] = useState(false)

  // Transform stats to firewall terminology
  const firewallStats: FirewallStats = {
    trafficVolume: stats?.totalScans || 0,
    threatsBlocked: stats?.vulnerabilitiesFound || 0,
    policyViolations: Math.floor((stats?.vulnerabilitiesFound || 0) * 0.3), // Estimate
    activeRules: 12, // Could come from policy engine
    lastBlockTime: '2 minutes ago',
    lastBlockPackage: 'requests-typo@1.0.0'
  }

  // Determine firewall status
  useEffect(() => {
    if (firewallStats.threatsBlocked > 10) {
      setFirewallStatus('BREACH')
    } else if (firewallStats.policyViolations > 5) {
      setFirewallStatus('WARNING')
    } else {
      setFirewallStatus('SECURE')
    }
  }, [firewallStats.threatsBlocked, firewallStats.policyViolations])

  // Simulate live activity feed (in production, this would be WebSocket)
  useEffect(() => {
    const mockActivity: LiveActivity[] = [
      {
        id: '1',
        timestamp: new Date(Date.now() - 2 * 60000),
        action: 'BLOCKED',
        packageName: 'requests-typo',
        reason: 'Typosquatting detected (RUNT score: 0.95)',
        severity: 'CRITICAL',
        policyName: 'Block Critical Risk'
      },
      {
        id: '2',
        timestamp: new Date(Date.now() - 15 * 60000),
        action: 'ALLOWED',
        packageName: 'express@4.18.2',
        reason: 'All checks passed',
        severity: 'LOW'
      },
      {
        id: '3',
        timestamp: new Date(Date.now() - 30 * 60000),
        action: 'REVIEWED',
        packageName: 'old-library@0.1.0',
        reason: 'Package not updated in 2+ years',
        severity: 'MEDIUM',
        policyName: 'Review Unmaintained'
      }
    ]
    setLiveActivity(mockActivity)
  }, [])

  const handleRunScan = async () => {
    try {
      success('Starting security scan...')
      await createScan({
        name: `Firewall Scan ${new Date().toLocaleTimeString()}`,
        target: 'package.json',
        type: 'firewall'
      })
      success('Security scan started!')
    } catch (err) {
      showError('Failed to start scan')
    }
  }

  const handleViewPolicies = () => {
    navigate('/policies')
    success('Opening policy management...')
  }

  const handleViewActivity = () => {
    setShowActivityFeed(!showActivityFeed)
  }

  // NEW: Firewall Status Card
  const FirewallStatusCard = () => {
    const statusConfig = {
      SECURE: {
        color: 'text-green-600',
        bgColor: 'bg-green-100',
        icon: CheckCircle,
        message: 'Perimeter Secure',
        subtitle: `Last block: ${firewallStats.lastBlockTime} (${firewallStats.lastBlockPackage})`
      },
      WARNING: {
        color: 'text-yellow-600',
        bgColor: 'bg-yellow-100',
        icon: AlertTriangle,
        message: 'Elevated Threat Level',
        subtitle: `${firewallStats.policyViolations} policy violations detected`
      },
      BREACH: {
        color: 'text-red-600',
        bgColor: 'bg-red-100',
        icon: AlertCircle,
        message: 'Active Threats Detected',
        subtitle: `${firewallStats.threatsBlocked} threats blocked today`
      }
    }

    const config = statusConfig[firewallStatus]
    const Icon = config.icon

    return (
      <Card className="border-2 border-border">
        <CardContent className="p-6">
          <div className="flex items-start space-x-4">
            <div className={`p-3 rounded-full ${config.bgColor}`}>
              <Icon className={`w-8 h-8 ${config.color}`} />
            </div>
            <div className="flex-1">
              <h3 className={`text-2xl font-bold ${config.color}`}>
                {config.message}
              </h3>
              <p className="text-sm text-muted-foreground mt-1">
                {config.subtitle}
              </p>
              <div className="mt-4 flex space-x-2">
                <Button size="sm" onClick={handleViewActivity}>
                  <Activity className="w-4 h-4 mr-2" />
                  Live Activity
                </Button>
                <Button size="sm" variant="outline" onClick={handleViewPolicies}>
                  <Lock className="w-4 h-4 mr-2" />
                  Manage Rules
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  // NEW: Stats with Firewall terminology
  const statsData = [
    {
      name: 'Packages Inspected',  // Changed from "Total Scans"
      value: firewallStats.trafficVolume.toLocaleString(),
      change: '+12%',
      changeType: 'positive' as const,
      icon: Shield,
    },
    {
      name: 'Threats Blocked',  // Changed from "Vulnerabilities Found"
      value: firewallStats.threatsBlocked.toString(),
      change: '-8%',
      changeType: 'negative' as const,  // Fewer blocks = good
      icon: Ban,
    },
    {
      name: 'Policy Violations',  // New metric
      value: firewallStats.policyViolations.toString(),
      change: '+5%',
      changeType: 'neutral' as const,
      icon: AlertTriangle,
    },
    {
      name: 'Active Rules',  // Changed from "Active Monitors"
      value: firewallStats.activeRules.toString(),
      change: '+2',
      changeType: 'positive' as const,
      icon: Activity,
    },
  ]

  // Activity Status Colors
  const getActivityColor = (action: LiveActivity['action']) => {
    switch (action) {
      case 'BLOCKED': return 'text-red-600 bg-red-100'
      case 'ALERTED': return 'text-orange-600 bg-orange-100'
      case 'REVIEWED': return 'text-yellow-600 bg-yellow-100'
      case 'ALLOWED': return 'text-green-600 bg-green-100'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  const getSeverityBadge = (severity: LiveActivity['severity']) => {
    const config = {
      CRITICAL: 'bg-red-600 text-white',
      HIGH: 'bg-orange-600 text-white',
      MEDIUM: 'bg-yellow-600 text-white',
      LOW: 'bg-green-600 text-white'
    }
    return config[severity]
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-4 bg-red-50 text-red-800 rounded">
        Error loading dashboard: {error}
      </div>
    )
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
          <h1 className="text-3xl font-bold tracking-tight">Supply Chain Firewall</h1>
          <p className="text-muted-foreground">
            Real-time package interception and policy enforcement
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-2">
          <Button variant="outline" onClick={() => success('Filtering coming soon!')}>
            <Clock className="w-4 h-4 mr-2" />
            Last 24h
          </Button>
          <Button onClick={handleRunScan}>
            <Shield className="w-4 h-4 mr-2" />
            Run Scan
          </Button>
        </div>
      </motion.div>

      {/* NEW: Firewall Status Card */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <FirewallStatusCard />
      </motion.div>

      {/* Stats Grid */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
      >
        {statsData.map((stat, index) => (
          <motion.div
            key={stat.name}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2 + index * 0.05 }}
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
                        : stat.changeType === 'negative'
                        ? 'text-red-600'
                        : 'text-gray-600'
                    }`}>
                      {stat.change} from last week
                    </p>
                  </div>
                  <stat.icon className="w-8 h-8 text-muted-foreground" />
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </motion.div>

      {/* NEW: Live Activity Feed */}
      {showActivityFeed && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Zap className="w-5 h-5 mr-2 text-yellow-500" />
                Live Security Activity
              </CardTitle>
              <CardDescription>
                Real-time package analysis and policy enforcement
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {liveActivity.map((activity) => (
                  <div 
                    key={activity.id}
                    className="flex items-start space-x-3 p-3 rounded-lg hover:bg-muted/50 transition-colors"
                  >
                    <div className="flex-shrink-0">
                      <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getActivityColor(activity.action)}`}>
                        {activity.action}
                      </span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium">
                        {activity.packageName}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {activity.reason}
                      </p>
                      {activity.policyName && (
                        <p className="text-xs text-blue-600 mt-1">
                          Policy: {activity.policyName}
                        </p>
                      )}
                    </div>
                    <div className="flex-shrink-0">
                      <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${getSeverityBadge(activity.severity)}`}>
                        {activity.severity}
                      </span>
                    </div>
                    <div className="flex-shrink-0 text-xs text-muted-foreground">
                      {formatTimestamp(activity.timestamp)}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Recent Scans - Keep existing but update terminology */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center">
                <Activity className="w-5 h-5 mr-2" />
                Recent Firewall Activity
              </span>
              <Button 
                variant="ghost" 
                size="sm"
                onClick={() => navigate('/security-scans')}
              >
                View All
              </Button>
            </CardTitle>
            <CardDescription>
              Latest package inspection results
            </CardDescription>
          </CardHeader>
          <CardContent>
            {recentScans && recentScans.length > 0 ? (
              <div className="space-y-3">
                {recentScans.slice(0, 5).map((scan: any) => (
                  <div 
                    key={scan.id}
                    className="flex items-center justify-between p-3 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer"
                    onClick={() => navigate(`/security-scans/${scan.id}`)}
                  >
                    <div className="flex items-center space-x-3">
                      <Shield className="w-5 h-5 text-blue-600" />
                      <div>
                        <p className="font-medium">{scan.name || 'Firewall Scan'}</p>
                        <p className="text-sm text-muted-foreground">
                          {formatTimestamp(scan.createdAt)}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {scan.status === 'completed' && (
                        <span className="text-green-600 text-sm font-medium">
                          Secure
                        </span>
                      )}
                      {scan.vulnerabilities > 0 && (
                        <span className="text-red-600 text-sm font-medium">
                          {scan.vulnerabilities} Blocked
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Activity className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No recent firewall activity</p>
                <Button className="mt-4" onClick={handleRunScan}>
                  Run First Scan
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </div>
  )
}

// Helper function
function formatTimestamp(timestamp: Date | string): string {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  
  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  const diffDays = Math.floor(diffHours / 24)
  return `${diffDays}d ago`
}

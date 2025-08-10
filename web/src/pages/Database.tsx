import { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  Database as DatabaseIcon, 
  Server, 
  HardDrive,
  Activity,
  RefreshCw,
  Download,
  Settings,
  AlertTriangle,
  CheckCircle,
  Clock,
  Archive,
  Search,
  Zap,
  Shield,
  Lock,
  Unlock,
  Eye,
  Plus,
  Calendar
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'

const databases = [
  {
    id: 'main-prod',
    name: 'Production Database',
    type: 'PostgreSQL',
    version: '15.2',
    status: 'healthy',
    size: '2.4 TB',
    connections: 45,
    maxConnections: 100,
    uptime: '99.9%',
    lastBackup: '2023-10-20 02:00:00',
    vulnerabilities: 0,
    securityScore: 9.2
  },
  {
    id: 'staging',
    name: 'Staging Database',
    type: 'PostgreSQL',
    version: '15.1',
    status: 'healthy',
    size: '856 GB',
    connections: 12,
    maxConnections: 50,
    uptime: '99.7%',
    lastBackup: '2023-10-20 02:15:00',
    vulnerabilities: 1,
    securityScore: 8.7
  },
  {
    id: 'analytics',
    name: 'Analytics Database',
    type: 'MongoDB',
    version: '6.0.3',
    status: 'warning',
    size: '1.8 TB',
    connections: 23,
    maxConnections: 75,
    uptime: '98.5%',
    lastBackup: '2023-10-19 23:45:00',
    vulnerabilities: 3,
    securityScore: 7.1
  },
  {
    id: 'cache',
    name: 'Redis Cache',
    type: 'Redis',
    version: '7.0.5',
    status: 'healthy',
    size: '45 GB',
    connections: 156,
    maxConnections: 500,
    uptime: '99.95%',
    lastBackup: '2023-10-20 01:30:00',
    vulnerabilities: 0,
    securityScore: 9.5
  }
]

const recentActivities = [
  {
    id: 1,
    type: 'backup',
    database: 'Production Database',
    action: 'Automated backup completed',
    timestamp: '2023-10-20 02:00:00',
    status: 'success',
    details: 'Full backup - 2.4 TB'
  },
  {
    id: 2,
    type: 'security',
    database: 'Analytics Database',
    action: 'Security scan detected vulnerabilities',
    timestamp: '2023-10-19 18:30:00',
    status: 'warning',
    details: '3 medium-severity issues found'
  },
  {
    id: 3,
    type: 'maintenance',
    database: 'Staging Database',
    action: 'Index optimization completed',
    timestamp: '2023-10-19 15:45:00',
    status: 'success',
    details: 'Performance improved by 15%'
  },
  {
    id: 4,
    type: 'connection',
    database: 'Redis Cache',
    action: 'Connection pool expanded',
    timestamp: '2023-10-19 12:20:00',
    status: 'info',
    details: 'Max connections increased to 500'
  }
]

const securityChecks = [
  {
    name: 'Encryption at Rest',
    status: 'enabled',
    description: 'All databases are encrypted using AES-256'
  },
  {
    name: 'SSL/TLS Connections',
    status: 'enabled',
    description: 'All connections use TLS 1.3 encryption'
  },
  {
    name: 'Access Control',
    status: 'enabled',
    description: 'Role-based access control is configured'
  },
  {
    name: 'Audit Logging',
    status: 'enabled',
    description: 'All database operations are logged'
  },
  {
    name: 'Backup Encryption',
    status: 'enabled',
    description: 'Backups are encrypted and stored securely'
  },
  {
    name: 'Vulnerability Scanning',
    status: 'warning',
    description: '1 database has pending security updates'
  }
]

export function Database() {
  const [activeTab, setActiveTab] = useState('overview')
  const [searchTerm, setSearchTerm] = useState('')

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="w-4 h-4 text-green-500" />
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />
      case 'error':
        return <AlertTriangle className="w-4 h-4 text-red-500" />
      default:
        return <Clock className="w-4 h-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-green-700 bg-green-100 border-green-200'
      case 'warning':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      case 'error':
        return 'text-red-700 bg-red-100 border-red-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'backup':
        return <Archive className="w-4 h-4 text-blue-500" />
      case 'security':
        return <Shield className="w-4 h-4 text-red-500" />
      case 'maintenance':
        return <Settings className="w-4 h-4 text-green-500" />
      case 'connection':
        return <Zap className="w-4 h-4 text-purple-500" />
      default:
        return <Activity className="w-4 h-4 text-gray-500" />
    }
  }

  const getActivityStatusColor = (status: string) => {
    switch (status) {
      case 'success':
        return 'text-green-600'
      case 'warning':
        return 'text-yellow-600'
      case 'error':
        return 'text-red-600'
      case 'info':
        return 'text-blue-600'
      default:
        return 'text-gray-600'
    }
  }

  const getSecurityIcon = (status: string) => {
    switch (status) {
      case 'enabled':
        return <Lock className="w-4 h-4 text-green-500" />
      case 'disabled':
        return <Unlock className="w-4 h-4 text-red-500" />
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />
      default:
        return <Shield className="w-4 h-4 text-gray-500" />
    }
  }

  const filteredDatabases = databases.filter(db =>
    db.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    db.type.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center sm:justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Database Management</h1>
          <p className="text-gray-600">
            Monitor and manage your database infrastructure
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-2">
          <Button variant="outline">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button variant="outline">
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
          <Button>
            <Plus className="w-4 h-4 mr-2" />
            Add Database
          </Button>
        </div>
      </motion.div>

      {/* Stats Cards */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-4 gap-4"
      >
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Databases</p>
                <p className="text-2xl font-bold">{databases.length}</p>
              </div>
              <DatabaseIcon className="w-8 h-8 text-blue-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Healthy</p>
                <p className="text-2xl font-bold text-green-600">
                  {databases.filter(db => db.status === 'healthy').length}
                </p>
              </div>
              <CheckCircle className="w-8 h-8 text-green-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Storage</p>
                <p className="text-2xl font-bold">5.1 TB</p>
              </div>
              <HardDrive className="w-8 h-8 text-purple-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Active Connections</p>
                <p className="text-2xl font-bold">236</p>
              </div>
              <Activity className="w-8 h-8 text-orange-500" />
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Tabs */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="border-b border-gray-200"
      >
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('overview')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'overview'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <DatabaseIcon className="w-4 h-4 inline mr-2" />
            Database Overview
          </button>
          <button
            onClick={() => setActiveTab('security')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'security'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <Shield className="w-4 h-4 inline mr-2" />
            Security
          </button>
          <button
            onClick={() => setActiveTab('activity')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'activity'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <Activity className="w-4 h-4 inline mr-2" />
            Recent Activity
          </button>
        </nav>
      </motion.div>

      {activeTab === 'overview' && (
        <>
          {/* Search */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="relative"
          >
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search databases..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 w-full bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </motion.div>

          {/* Database List */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="space-y-4"
          >
            {filteredDatabases.map((database, index) => (
              <motion.div
                key={database.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 * index }}
              >
                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-6">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-3">
                          <Server className="w-6 h-6 text-blue-500" />
                          <div>
                            <h3 className="text-lg font-semibold">{database.name}</h3>
                            <p className="text-sm text-gray-600">{database.type} {database.version}</p>
                          </div>
                          <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(database.status)}`}>
                            {getStatusIcon(database.status)}
                            <span className="ml-1">{database.status.toUpperCase()}</span>
                          </span>
                        </div>
                        
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                          <div>
                            <p className="text-xs text-gray-600">Size</p>
                            <p className="font-medium">{database.size}</p>
                          </div>
                          <div>
                            <p className="text-xs text-gray-600">Connections</p>
                            <p className="font-medium">{database.connections}/{database.maxConnections}</p>
                          </div>
                          <div>
                            <p className="text-xs text-gray-600">Uptime</p>
                            <p className="font-medium">{database.uptime}</p>
                          </div>
                          <div>
                            <p className="text-xs text-gray-600">Security Score</p>
                            <p className="font-medium">{database.securityScore}/10</p>
                          </div>
                        </div>

                        <div className="flex items-center space-x-4 text-sm text-gray-600">
                          <div className="flex items-center">
                            <Calendar className="w-4 h-4 mr-1" />
                            Last backup: {database.lastBackup}
                          </div>
                          {database.vulnerabilities > 0 && (
                            <div className="flex items-center text-red-600">
                              <AlertTriangle className="w-4 h-4 mr-1" />
                              {database.vulnerabilities} vulnerabilities
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div className="flex space-x-2 ml-4">
                        <Button variant="outline" size="sm">
                          <Eye className="w-4 h-4 mr-1" />
                          Monitor
                        </Button>
                        <Button variant="outline" size="sm">
                          <Settings className="w-4 h-4 mr-1" />
                          Configure
                        </Button>
                        <Button variant="outline" size="sm">
                          <Archive className="w-4 h-4 mr-1" />
                          Backup
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </motion.div>
        </>
      )}

      {activeTab === 'security' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="space-y-6"
        >
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Shield className="w-5 h-5 mr-2" />
                Security Checks
              </CardTitle>
              <CardDescription>
                Database security configuration and compliance status
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {securityChecks.map((check, index) => (
                  <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      {getSecurityIcon(check.status)}
                      <div>
                        <p className="font-medium">{check.name}</p>
                        <p className="text-sm text-gray-600">{check.description}</p>
                      </div>
                    </div>
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                      check.status === 'enabled' ? 'bg-green-100 text-green-700' :
                      check.status === 'warning' ? 'bg-yellow-100 text-yellow-700' :
                      'bg-red-100 text-red-700'
                    }`}>
                      {check.status.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {activeTab === 'activity' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="space-y-4"
        >
          {recentActivities.map((activity, index) => (
            <motion.div
              key={activity.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 * index }}
            >
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-start space-x-3">
                    {getActivityIcon(activity.type)}
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <h4 className="font-medium">{activity.action}</h4>
                        <span className={`text-sm ${getActivityStatusColor(activity.status)}`}>
                          {activity.status.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 mt-1">{activity.database}</p>
                      <p className="text-xs text-gray-500 mt-1">{activity.details}</p>
                      <p className="text-xs text-gray-400 mt-2">{activity.timestamp}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </motion.div>
      )}
    </div>
  )
}
import { useState, useEffect } from 'react'
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
  Calendar,
  X,
  Play,
  Pause,
  BarChart3,
  Cpu,
  HardDrive as MemoryIcon,
  Network,
  Save,
  RotateCcw
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { apiService, type DatabaseInstance, type DatabaseActivity, type DatabaseSecurityCheck } from '../services/api'



export function Database() {
  const [activeTab, setActiveTab] = useState('overview')
  const [searchTerm, setSearchTerm] = useState('')
  const [databases, setDatabases] = useState<DatabaseInstance[]>([])
  const [recentActivities, setRecentActivities] = useState<DatabaseActivity[]>([])
  const [securityChecks, setSecurityChecks] = useState<DatabaseSecurityCheck[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  
  // Modal states
  const [monitorModal, setMonitorModal] = useState<{ isOpen: boolean; database: DatabaseInstance | null; metrics: any | null; recentQueries: any[] | null }>({ isOpen: false, database: null, metrics: null, recentQueries: null })
  const [configureModal, setConfigureModal] = useState<{ isOpen: boolean; database: DatabaseInstance | null; config: any | null }>({ isOpen: false, database: null, config: null })
  const [backupModal, setBackupModal] = useState<{ isOpen: boolean; database: DatabaseInstance | null; backups: any[] | null }>({ isOpen: false, database: null, backups: null })

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true)
        const [databasesResponse, activitiesResponse, securityResponse] = await Promise.all([
          apiService.getAllDatabases(),
          apiService.getDatabaseActivity(),
          apiService.getDatabaseSecurity()
        ])
        
        setDatabases(databasesResponse.databases)
        setRecentActivities(activitiesResponse.activities)
        setSecurityChecks(securityResponse.securityChecks)
        setError(null)
      } catch (err) {
        console.error('Failed to fetch database data:', err)
        setError('Failed to load database information')
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [])

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

  const handleMonitorDatabase = async (database: DatabaseInstance) => {
    try {
      setMonitorModal({ isOpen: true, database, metrics: null, recentQueries: null })
      const [metrics, queriesResponse] = await Promise.all([
        apiService.getDatabaseInstanceStatus(database.id),
        apiService.getDatabaseRecentQueries(database.id, 5)
      ])
      setMonitorModal({ isOpen: true, database, metrics, recentQueries: queriesResponse.queries })
    } catch (error) {
      console.error('Failed to fetch database metrics:', error)
      setMonitorModal({ isOpen: true, database, metrics: null, recentQueries: null })
    }
  }

  const handleConfigureDatabase = async (database: DatabaseInstance) => {
    try {
      setConfigureModal({ isOpen: true, database, config: null })
      // For now, we'll use the database instance data as config since there's no specific config endpoint
      const config = {
        host: 'localhost',
        port: database.type === 'postgresql' ? 5432 : database.type === 'mysql' ? 3306 : 27017,
        maxConnections: database.maxConnections,
        currentConnections: database.connections,
        version: database.version,
        type: database.type
      }
      setConfigureModal({ isOpen: true, database, config })
    } catch (error) {
      console.error('Failed to fetch database config:', error)
      setConfigureModal({ isOpen: true, database, config: null })
    }
  }

  const handleBackupDatabase = async (database: DatabaseInstance) => {
    try {
      setBackupModal({ isOpen: true, database, backups: null })
      // Create mock backup data since there's no specific backup endpoint
      const backups = [
        {
          id: '1',
          name: `${database.name}_backup_${new Date().toISOString().split('T')[0]}`,
          date: database.lastBackup || new Date().toISOString(),
          size: '2.3 GB',
          status: 'completed',
          type: 'full'
        },
        {
          id: '2',
          name: `${database.name}_backup_${new Date(Date.now() - 86400000).toISOString().split('T')[0]}`,
          date: new Date(Date.now() - 86400000).toISOString(),
          size: '2.1 GB',
          status: 'completed',
          type: 'incremental'
        }
      ]
      setBackupModal({ isOpen: true, database, backups })
    } catch (error) {
      console.error('Failed to fetch backup data:', error)
      setBackupModal({ isOpen: true, database, backups: [] })
    }
  }

  const closeMonitorModal = () => {
    setMonitorModal({ isOpen: false, database: null, metrics: null, recentQueries: null })
  }

  const closeConfigureModal = () => {
    setConfigureModal({ isOpen: false, database: null, config: null })
  }

  const closeBackupModal = () => {
    setBackupModal({ isOpen: false, database: null, backups: null })
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
        <span className="ml-2 text-lg">Loading database information...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <AlertTriangle className="w-8 h-8 text-red-500" />
        <span className="ml-2 text-lg text-red-600">{error}</span>
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
                <p className="text-2xl font-bold">
                  {databases.reduce((total, db) => {
                    const sizeValue = parseFloat(db.size.replace(/[^0-9.]/g, '')) || 0
                    const unit = db.size.includes('TB') ? 1024 : db.size.includes('MB') ? 0.001 : 1
                    return total + (sizeValue * unit)
                  }, 0).toFixed(1)} GB
                </p>
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
                <p className="text-2xl font-bold">
                  {databases.reduce((total, db) => total + db.connections, 0)}
                </p>
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
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => handleMonitorDatabase(database)}
                        >
                          <Eye className="w-4 h-4 mr-1" />
                          Monitor
                        </Button>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => handleConfigureDatabase(database)}
                        >
                          <Settings className="w-4 h-4 mr-1" />
                          Configure
                        </Button>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => handleBackupDatabase(database)}
                        >
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

      {/* Monitor Modal */}
      {monitorModal.isOpen && monitorModal.database && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-white rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto"
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold flex items-center">
                  <BarChart3 className="w-6 h-6 mr-2 text-blue-600" />
                  Monitor {monitorModal.database.name}
                </h2>
                <Button variant="outline" size="sm" onClick={closeMonitorModal}>
                  <X className="w-4 h-4" />
                </Button>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center">
                      <Cpu className="w-4 h-4 mr-2" />
                      CPU Usage
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {monitorModal.metrics ? (
                      <>
                        <div className={`text-2xl font-bold ${
                          monitorModal.metrics.cpuUsage > 80 ? 'text-red-600' : 
                          monitorModal.metrics.cpuUsage > 60 ? 'text-yellow-600' : 'text-green-600'
                        }`}>
                          {monitorModal.metrics.cpuUsage.toFixed(2)}%
                        </div>
                        <div className="text-xs text-gray-500">
                          {monitorModal.metrics.cpuUsage > 80 ? 'High' : 
                           monitorModal.metrics.cpuUsage > 60 ? 'Moderate' : 'Normal'}
                        </div>
                      </>
                    ) : (
                      <div className="text-sm text-gray-500">Loading...</div>
                    )}
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center">
                      <MemoryIcon className="w-4 h-4 mr-2" />
                      Memory Usage
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {monitorModal.metrics ? (
                      <>
                        <div className={`text-2xl font-bold ${
                          monitorModal.metrics.memoryUsage > 80 ? 'text-red-600' : 
                          monitorModal.metrics.memoryUsage > 60 ? 'text-yellow-600' : 'text-green-600'
                        }`}>
                          {monitorModal.metrics.memoryUsage.toFixed(2)}%
                        </div>
                        <div className="text-xs text-gray-500">
                          {monitorModal.metrics.memoryUsage > 80 ? 'High' : 
                           monitorModal.metrics.memoryUsage > 60 ? 'Moderate' : 'Normal'}
                        </div>
                      </>
                    ) : (
                      <div className="text-sm text-gray-500">Loading...</div>
                    )}
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center">
                      <Network className="w-4 h-4 mr-2" />
                      Connections
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {monitorModal.metrics ? (
                      <>
                        <div className="text-2xl font-bold text-blue-600">
                          {monitorModal.database?.connections || 0}
                        </div>
                        <div className="text-xs text-gray-500">Active</div>
                      </>
                    ) : (
                      <div className="text-sm text-gray-500">Loading...</div>
                    )}
                  </CardContent>
                </Card>
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle>Recent Queries</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {monitorModal.recentQueries && monitorModal.recentQueries.length > 0 ? (
                      <div className="space-y-2">
                        {monitorModal.recentQueries.map((query, index) => (
                          <div key={index} className="text-sm p-2 bg-gray-50 rounded">
                            <div className="font-mono text-xs" title={query.query}>
                              {query.query.length > 80 ? `${query.query.substring(0, 80)}...` : query.query}
                            </div>
                            <div className="text-xs text-gray-500 mt-1 flex justify-between">
                              <span>Duration: {query.duration}</span>
                              <span>Calls: {query.calls}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-sm text-gray-500">No recent queries available</div>
                    )}
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader>
                    <CardTitle>Performance Metrics</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {monitorModal.metrics ? (
                      <div className="space-y-3">
                        <div className="flex justify-between">
                          <span className="text-sm">Avg Query Time</span>
                          <span className="text-sm font-medium">
                            {monitorModal.metrics.performanceMetrics?.avgQueryTime 
                              ? `${monitorModal.metrics.performanceMetrics.avgQueryTime.toFixed(1)}ms` 
                              : 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-sm">Queries/sec</span>
                          <span className="text-sm font-medium">
                            {monitorModal.metrics.performanceMetrics?.queriesPerSec 
                              ? monitorModal.metrics.performanceMetrics.queriesPerSec.toFixed(1) 
                              : 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-sm">Cache Hit Rate</span>
                          <span className="text-sm font-medium">
                            {monitorModal.metrics.performanceMetrics?.cacheHitRate 
                              ? `${monitorModal.metrics.performanceMetrics.cacheHitRate.toFixed(1)}%` 
                              : 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-sm">Disk Usage</span>
                          <span className="text-sm font-medium">{monitorModal.metrics.diskUsage}%</span>
                        </div>
                      </div>
                    ) : (
                      <div className="text-sm text-gray-500">Loading metrics...</div>
                    )}
                  </CardContent>
                </Card>

                {/* Cache Metrics */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center">
                      <HardDrive className="w-5 h-5 mr-2 text-purple-600" />
                      Cache Metrics
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {monitorModal.metrics?.cacheMetrics ? (
                      <div className="space-y-3">
                        <div className="flex justify-between">
                          <span className="text-sm">Cache Size</span>
                          <span className="text-sm font-medium">
                            {monitorModal.metrics.cacheMetrics.cacheSize || 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-sm">Cache Used</span>
                          <span className="text-sm font-medium">
                            {monitorModal.metrics.cacheMetrics.cacheUsed || 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-sm">Cache Utilization</span>
                          <span className="text-sm font-medium">
                            {monitorModal.metrics.cacheMetrics.cacheUtilization != null 
                              ? `${monitorModal.metrics.cacheMetrics.cacheUtilization.toFixed(1)}%` 
                              : 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-sm">Cache Evictions</span>
                          <span className="text-sm font-medium">
                            {monitorModal.metrics.cacheMetrics.cacheEvictions != null 
                              ? monitorModal.metrics.cacheMetrics.cacheEvictions.toLocaleString() 
                              : 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-sm">Hit Rate</span>
                          <span className="text-sm font-medium">
                            {monitorModal.metrics.cacheMetrics.hitRate != null 
                              ? `${monitorModal.metrics.cacheMetrics.hitRate.toFixed(1)}%` 
                              : 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-sm">Miss Rate</span>
                          <span className="text-sm font-medium">
                            {monitorModal.metrics.cacheMetrics.missRate != null 
                              ? `${monitorModal.metrics.cacheMetrics.missRate.toFixed(1)}%` 
                              : 'N/A'}
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div className="text-sm text-gray-500">No cache metrics available</div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>
          </motion.div>
        </div>
      )}

      {/* Configure Modal */}
      {configureModal.isOpen && configureModal.database && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto"
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold flex items-center">
                  <Settings className="w-6 h-6 mr-2 text-blue-600" />
                  Configure {configureModal.database.name}
                </h2>
                <Button variant="outline" size="sm" onClick={closeConfigureModal}>
                  <X className="w-4 h-4" />
                </Button>
              </div>
              
              <div className="space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle>Connection Settings</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {configureModal.config ? (
                      <>
                        <div>
                          <label className="block text-sm font-medium mb-1">Host</label>
                          <input 
                            type="text" 
                            defaultValue={configureModal.config.host}
                            className="w-full p-2 border rounded-md"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium mb-1">Port</label>
                          <input 
                            type="number" 
                            defaultValue={configureModal.config.port}
                            className="w-full p-2 border rounded-md"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium mb-1">Max Connections</label>
                          <input 
                            type="number" 
                            defaultValue={configureModal.config.maxConnections}
                            className="w-full p-2 border rounded-md"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium mb-1">Current Connections</label>
                          <input 
                            type="number" 
                            value={configureModal.config.currentConnections}
                            disabled
                            className="w-full p-2 border rounded-md bg-gray-50"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium mb-1">Database Type</label>
                          <input 
                            type="text" 
                            value={configureModal.config.type}
                            disabled
                            className="w-full p-2 border rounded-md bg-gray-50"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium mb-1">Version</label>
                          <input 
                            type="text" 
                            value={configureModal.config.version}
                            disabled
                            className="w-full p-2 border rounded-md bg-gray-50"
                          />
                        </div>
                      </>
                    ) : (
                      <div className="text-sm text-gray-500">Loading configuration...</div>
                    )}
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader>
                    <CardTitle>Security Settings</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">SSL/TLS Encryption</span>
                      <input type="checkbox" className="rounded" />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Require Authentication</span>
                      <input type="checkbox" defaultChecked className="rounded" />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Enable Audit Logging</span>
                      <input type="checkbox" defaultChecked className="rounded" />
                    </div>
                  </CardContent>
                </Card>
                
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={closeConfigureModal}>
                    Cancel
                  </Button>
                  <Button onClick={() => {
                    alert('Configuration saved successfully!')
                    closeConfigureModal()
                  }}>
                    <Save className="w-4 h-4 mr-2" />
                    Save Changes
                  </Button>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      )}

      {/* Backup Modal */}
      {backupModal.isOpen && backupModal.database && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto"
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold flex items-center">
                  <Archive className="w-6 h-6 mr-2 text-blue-600" />
                  Backup {backupModal.database.name}
                </h2>
                <Button variant="outline" size="sm" onClick={closeBackupModal}>
                  <X className="w-4 h-4" />
                </Button>
              </div>
              
              <div className="space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle>Create New Backup</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium mb-1">Backup Name</label>
                      <input 
                        type="text" 
                        defaultValue={`${backupModal.database.name}_${new Date().toISOString().split('T')[0]}`}
                        className="w-full p-2 border rounded-md"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium mb-1">Backup Type</label>
                      <select className="w-full p-2 border rounded-md">
                        <option value="full">Full Backup</option>
                        <option value="incremental">Incremental Backup</option>
                        <option value="differential">Differential Backup</option>
                      </select>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Compress Backup</span>
                      <input type="checkbox" defaultChecked className="rounded" />
                    </div>
                  </CardContent>
                </Card>
                
                <Card>
                  <CardHeader>
                    <CardTitle>Recent Backups</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {backupModal.backups ? (
                      <div className="space-y-2">
                        {backupModal.backups.length > 0 ? (
                          backupModal.backups.map((backup) => (
                            <div key={backup.id} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                              <div>
                                <div className="text-sm font-medium">{backup.name}</div>
                                <div className="text-xs text-gray-500">
                                  {backup.type} backup • {backup.size} • {new Date(backup.date).toLocaleDateString()}
                                </div>
                              </div>
                              <div className="flex items-center space-x-2">
                                <span className={`text-xs px-2 py-1 rounded ${
                                  backup.status === 'completed' ? 'bg-green-100 text-green-700' :
                                  backup.status === 'running' ? 'bg-blue-100 text-blue-700' :
                                  'bg-red-100 text-red-700'
                                }`}>
                                  {backup.status}
                                </span>
                                <Button variant="outline" size="sm">
                                  <RotateCcw className="w-4 h-4 mr-1" />
                                  Restore
                                </Button>
                              </div>
                            </div>
                          ))
                        ) : (
                          <div className="text-sm text-gray-500 text-center py-4">
                            No backups found for this database
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-sm text-gray-500">Loading backups...</div>
                    )}
                  </CardContent>
                </Card>
                
                <div className="flex justify-end space-x-2">
                  <Button variant="outline" onClick={closeBackupModal}>
                    Cancel
                  </Button>
                  <Button onClick={() => {
                    alert('Backup initiated successfully!')
                    closeBackupModal()
                  }}>
                    <Archive className="w-4 h-4 mr-2" />
                    Start Backup
                  </Button>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  )
}
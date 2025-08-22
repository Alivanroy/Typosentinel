import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { apiService, type Integration } from '../services/api'
import { 
  Plug, 
  Settings, 
  Check, 
  Plus,
  ExternalLink,
  AlertCircle,
  Clock,
  Database,
  MessageSquare,
  Mail,
  Webhook,
  Key,
  Globe,
  GitBranch,
  Server,
  Cloud,
  Zap,
  Bell,
  Eye,
  Trash2
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'

// Icon mapping for integrations
const getIntegrationIcon = (iconName: string) => {
  const iconMap: Record<string, any> = {
    github: GitBranch,
    slack: MessageSquare,
    jira: AlertCircle,
    jenkins: Server,
    email: Mail,
    webhook: Webhook,
    aws: Cloud,
    splunk: Database
  }
  return iconMap[iconName] || Plug
}

// Color mapping for integrations
const getIntegrationColor = (category: string) => {
  const colorMap: Record<string, string> = {
    source_control: 'text-gray-900 bg-gray-100',
    notifications: 'text-purple-600 bg-purple-100',
    issue_tracking: 'text-blue-600 bg-blue-100',
    ci_cd: 'text-orange-600 bg-orange-100',
    custom: 'text-green-600 bg-green-100',
    cloud_security: 'text-yellow-600 bg-yellow-100',
    siem: 'text-indigo-600 bg-indigo-100'
  }
  return colorMap[category] || 'text-gray-600 bg-gray-100'
}

// Category mapping
const getCategoryDisplayName = (category: string) => {
  const categoryMap: Record<string, string> = {
    source_control: 'Version Control',
    notifications: 'Communication',
    issue_tracking: 'Project Management',
    ci_cd: 'CI/CD',
    custom: 'API',
    cloud_security: 'Cloud Security',
    siem: 'SIEM'
  }
  return categoryMap[category] || category
}

const categories = ['All', 'Version Control', 'Communication', 'CI/CD', 'Cloud Security', 'SIEM', 'API', 'Project Management']

export function Integrations() {
  const [integrations, setIntegrations] = useState<Integration[]>([])
  // const [loading, setLoading] = useState(true)
  // const [error, setError] = useState<string | null>(null)
  const [selectedCategory, setSelectedCategory] = useState('All')
  const [searchTerm, setSearchTerm] = useState('')

  // Fetch integrations from API
  useEffect(() => {
    const fetchIntegrations = async () => {
      try {
        // setLoading(true)
        const response = await apiService.getAllIntegrations()
        setIntegrations(response)
        // setError(null)
      } catch (err) {
        console.error('Failed to fetch integrations:', err)
        // setError('Failed to load integrations')
      } finally {
        // setLoading(false)
      }
    }

    fetchIntegrations()
  }, [])

  // Derived state
  const connectedIntegrations = integrations.filter(i => i.status === 'connected')
  const availableIntegrations = integrations.filter(i => i.status === 'disconnected')
  const [activeTab, setActiveTab] = useState('all')

  const filteredIntegrations = integrations.filter(integration => {
    const matchesSearch = integration.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         integration.description.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesCategory = selectedCategory === 'All' || getCategoryDisplayName(integration.category) === selectedCategory
    const matchesTab = activeTab === 'all' || 
                      (activeTab === 'connected' && integration.status === 'connected') ||
                      (activeTab === 'available' && integration.status === 'disconnected')
    return matchesSearch && matchesCategory && matchesTab
  })

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected':
        return <Check className="w-4 h-4 text-green-500" />
      case 'disconnected':
        return <Plus className="w-4 h-4 text-gray-500" />
      case 'error':
        return <AlertCircle className="w-4 h-4 text-red-500" />
      default:
        return <Clock className="w-4 h-4 text-yellow-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected':
        return 'text-green-700 bg-green-100 border-green-200'
      case 'available':
        return 'text-gray-700 bg-gray-100 border-gray-200'
      case 'configuring':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
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
          <h1 className="text-3xl font-bold tracking-tight">Integrations</h1>
          <p className="text-gray-600">
            Connect TypoSentinel with your favorite tools and services
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-2">
          <Button variant="outline">
            <Key className="w-4 h-4 mr-2" />
            API Keys
          </Button>
          <Button>
            <Plus className="w-4 h-4 mr-2" />
            Add Integration
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
                <p className="text-sm font-medium text-gray-600">Connected</p>
                <p className="text-2xl font-bold text-green-600">{connectedIntegrations.length}</p>
              </div>
              <Check className="w-8 h-8 text-green-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Available</p>
                <p className="text-2xl font-bold text-blue-600">{availableIntegrations.length}</p>
              </div>
              <Plug className="w-8 h-8 text-blue-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Categories</p>
                <p className="text-2xl font-bold text-purple-600">{categories.length - 1}</p>
              </div>
              <Settings className="w-8 h-8 text-purple-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Active Alerts</p>
                <p className="text-2xl font-bold text-orange-600">
                  {integrations.filter(i => i.status === 'error').length}
                </p>
              </div>
              <Bell className="w-8 h-8 text-orange-500" />
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
            onClick={() => setActiveTab('all')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'all'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <Globe className="w-4 h-4 inline mr-2" />
            All Integrations
          </button>
          <button
            onClick={() => setActiveTab('connected')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'connected'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <Check className="w-4 h-4 inline mr-2" />
            Connected ({connectedIntegrations.length})
          </button>
          <button
            onClick={() => setActiveTab('available')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'available'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <Plus className="w-4 h-4 inline mr-2" />
            Available ({availableIntegrations.length})
          </button>
        </nav>
      </motion.div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="flex flex-col sm:flex-row gap-4"
      >
        <div className="relative flex-1">
          <input
            type="text"
            placeholder="Search integrations..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-4 pr-4 py-2 w-full bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-wrap gap-2">
          {categories.map((category) => (
            <button
              key={category}
              onClick={() => setSelectedCategory(category)}
              className={`px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                selectedCategory === category
                  ? 'bg-blue-100 text-blue-700 border border-blue-200'
                  : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'
              }`}
            >
              {category}
            </button>
          ))}
        </div>
      </motion.div>

      {/* Integrations Grid */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
      >
        {filteredIntegrations.map((integration, index) => (
          <motion.div
            key={integration.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 * index }}
          >
            <Card className="hover:shadow-md transition-shadow h-full">
              <CardContent className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <div className={`w-12 h-12 rounded-lg ${getIntegrationColor(integration.category)} flex items-center justify-center`}>
                      {(() => {
                        const IconComponent = getIntegrationIcon(integration.icon)
                        return <IconComponent className="w-6 h-6" />
                      })()}
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold">{integration.name}</h3>
                      <span className="text-sm text-gray-600">{getCategoryDisplayName(integration.category)}</span>
                    </div>
                  </div>
                  <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(integration.status)}`}>
                    {getStatusIcon(integration.status)}
                    <span className="ml-1">{integration.status.toUpperCase()}</span>
                  </span>
                </div>
                
                <p className="text-gray-700 text-sm mb-4">{integration.description}</p>
                
                <div className="space-y-3 mb-4">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-600">Last sync:</span>
                    <span className="font-medium">
                      {integration.lastSync ? new Date(integration.lastSync).toLocaleDateString() : 'Never'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-600">Features:</span>
                    <span className="font-medium">{integration.features.length} available</span>
                  </div>
                </div>

                <div className="mb-4">
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Features:</h4>
                  <ul className="space-y-1">
                    {integration.features.map((feature, idx) => (
                      <li key={idx} className="flex items-center text-sm text-gray-600">
                        <Check className="w-3 h-3 text-green-500 mr-2 flex-shrink-0" />
                        {feature}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="flex space-x-2">
                  {integration.status === 'connected' ? (
                    <>
                      <Button variant="outline" size="sm" className="flex-1">
                        <Settings className="w-4 h-4 mr-1" />
                        Configure
                      </Button>
                      <Button variant="outline" size="sm">
                        <Eye className="w-4 h-4" />
                      </Button>
                      <Button variant="outline" size="sm">
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </>
                  ) : (
                    <>
                      <Button size="sm" className="flex-1">
                        <Plus className="w-4 h-4 mr-1" />
                        Connect
                      </Button>
                      <Button variant="outline" size="sm">
                        <ExternalLink className="w-4 h-4" />
                      </Button>
                    </>
                  )}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </motion.div>

      {filteredIntegrations.length === 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-12"
        >
          <Plug className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No integrations found</h3>
          <p className="text-gray-600">
            {searchTerm || selectedCategory !== 'All'
              ? 'Try adjusting your filters to see more results.'
              : 'Start by connecting your first integration.'}
          </p>
        </motion.div>
      )}

      {/* Connected Integrations Summary */}
      {connectedIntegrations.length > 0 && activeTab === 'connected' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <Zap className="w-5 h-5 mr-2" />
                Integration Activity
              </CardTitle>
              <CardDescription>
                Recent activity from your connected integrations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {connectedIntegrations.length > 0 ? (
                  connectedIntegrations.slice(0, 3).map((integration, index) => {
                    const IconComponent = getIntegrationIcon(integration.icon)
                    const colorClass = integration.category === 'source_control' ? 'bg-green-50 text-green-600' :
                                     integration.category === 'notifications' ? 'bg-blue-50 text-blue-600' :
                                     'bg-purple-50 text-purple-600'
                    const statusColor = integration.status === 'connected' ? 'text-green-500' : 'text-gray-500'
                    
                    return (
                      <div key={integration.id} className={`flex items-center justify-between p-3 rounded-lg ${colorClass.split(' ')[0]}`}>
                        <div className="flex items-center space-x-3">
                          <IconComponent className={`w-5 h-5 ${colorClass.split(' ')[1]}`} />
                          <div>
                            <p className="text-sm font-medium">{integration.name} integration active</p>
                            <p className="text-xs text-gray-600">
                              Last sync: {integration.lastSync ? new Date(integration.lastSync).toLocaleDateString() : 'Never'}
                            </p>
                          </div>
                        </div>
                        <Check className={`w-5 h-5 ${statusColor}`} />
                      </div>
                    )
                  })
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <p className="text-sm">No connected integrations to show activity for.</p>
                    <p className="text-xs mt-1">Connect an integration to see activity here.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}
    </div>
  )
}
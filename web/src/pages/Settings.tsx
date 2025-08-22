import { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  User, 
  Shield, 
  Bell,
  Globe,
  Key,
  Smartphone,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  Save,
  RefreshCw,
  Download,
  Upload,
  Trash2,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Monitor,
  Moon,
  Sun,
  Palette,
  Volume2,
  VolumeX,
  Server,
  Zap
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'

const settingsCategories = [
  {
    id: 'profile',
    name: 'Profile',
    icon: User,
    description: 'Manage your personal information'
  },
  {
    id: 'security',
    name: 'Security',
    icon: Shield,
    description: 'Security settings and authentication'
  },
  {
    id: 'notifications',
    name: 'Notifications',
    icon: Bell,
    description: 'Configure notification preferences'
  },
  {
    id: 'appearance',
    name: 'Appearance',
    icon: Palette,
    description: 'Customize the interface'
  },
  {
    id: 'integrations',
    name: 'Integrations',
    icon: Globe,
    description: 'Manage external integrations'
  },
  {
    id: 'system',
    name: 'System',
    icon: Server,
    description: 'System configuration and maintenance'
  }
]

const notificationSettings = [
  {
    id: 'vulnerability_alerts',
    name: 'Vulnerability Alerts',
    description: 'Get notified when new vulnerabilities are found',
    enabled: true,
    channels: ['email', 'push', 'slack']
  },
  {
    id: 'scan_completion',
    name: 'Scan Completion',
    description: 'Notifications when security scans complete',
    enabled: true,
    channels: ['email', 'push']
  },
  {
    id: 'report_generation',
    name: 'Report Generation',
    description: 'Alerts when reports are ready',
    enabled: false,
    channels: ['email']
  },
  {
    id: 'system_updates',
    name: 'System Updates',
    description: 'Important system and security updates',
    enabled: true,
    channels: ['email', 'push', 'slack']
  },
  {
    id: 'team_activity',
    name: 'Team Activity',
    description: 'Updates on team member activities',
    enabled: false,
    channels: ['email']
  }
]

const integrationServices = [
  {
    id: 'slack',
    name: 'Slack',
    description: 'Send notifications to Slack channels',
    connected: true,
    lastSync: '2023-10-20 14:30:00'
  },
  {
    id: 'jira',
    name: 'Jira',
    description: 'Create tickets for vulnerabilities',
    connected: true,
    lastSync: '2023-10-20 13:45:00'
  },
  {
    id: 'github',
    name: 'GitHub',
    description: 'Monitor repositories for security issues',
    connected: false,
    lastSync: null
  },
  {
    id: 'aws',
    name: 'AWS',
    description: 'Scan AWS infrastructure',
    connected: true,
    lastSync: '2023-10-20 12:15:00'
  }
]

export function Settings() {
  const [activeCategory, setActiveCategory] = useState('profile')
  const [showPassword, setShowPassword] = useState(false)
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(true)
  const [darkMode, setDarkMode] = useState(false)
  const [soundEnabled, setSoundEnabled] = useState(true)
  const [autoScan, setAutoScan] = useState(true)

  const renderProfileSettings = () => (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Personal Information</CardTitle>
          <CardDescription>Update your personal details</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                First Name
              </label>
              <input
                type="text"
                defaultValue="John"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Last Name
              </label>
              <input
                type="text"
                defaultValue="Doe"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Email Address
            </label>
            <input
              type="email"
              defaultValue="john.doe@company.com"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Phone Number
            </label>
            <input
              type="tel"
              defaultValue="+1 (555) 123-4567"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Job Title
            </label>
            <input
              type="text"
              defaultValue="Security Engineer"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <Button>
            <Save className="w-4 h-4 mr-2" />
            Save Changes
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Change Password</CardTitle>
          <CardDescription>Update your account password</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Current Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                className="w-full px-3 py-2 pr-10 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              New Password
            </label>
            <input
              type="password"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Confirm New Password
            </label>
            <input
              type="password"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <Button>
            <Lock className="w-4 h-4 mr-2" />
            Update Password
          </Button>
        </CardContent>
      </Card>
    </div>
  )

  const renderSecuritySettings = () => (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Two-Factor Authentication</CardTitle>
          <CardDescription>Add an extra layer of security to your account</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              {twoFactorEnabled ? (
                <Lock className="w-5 h-5 text-green-500" />
              ) : (
                <Unlock className="w-5 h-5 text-red-500" />
              )}
              <div>
                <p className="font-medium">
                  Two-Factor Authentication is {twoFactorEnabled ? 'Enabled' : 'Disabled'}
                </p>
                <p className="text-sm text-gray-600">
                  {twoFactorEnabled 
                    ? 'Your account is protected with 2FA'
                    : 'Enable 2FA to secure your account'
                  }
                </p>
              </div>
            </div>
            <Button
              variant={twoFactorEnabled ? 'outline' : 'default'}
              onClick={() => setTwoFactorEnabled(!twoFactorEnabled)}
            >
              {twoFactorEnabled ? 'Disable' : 'Enable'} 2FA
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>API Keys</CardTitle>
          <CardDescription>Manage your API access keys</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between p-3 bg-gray-50 rounded-md">
            <div>
              <p className="font-medium">Production API Key</p>
              <p className="text-sm text-gray-600">sk-prod-••••••••••••••••</p>
              <p className="text-xs text-gray-500">Created: Oct 15, 2023</p>
            </div>
            <div className="flex space-x-2">
              <Button variant="outline" size="sm">
                <RefreshCw className="w-4 h-4 mr-1" />
                Regenerate
              </Button>
              <Button variant="outline" size="sm">
                <Trash2 className="w-4 h-4" />
              </Button>
            </div>
          </div>
          <div className="flex items-center justify-between p-3 bg-gray-50 rounded-md">
            <div>
              <p className="font-medium">Development API Key</p>
              <p className="text-sm text-gray-600">sk-dev-••••••••••••••••</p>
              <p className="text-xs text-gray-500">Created: Oct 10, 2023</p>
            </div>
            <div className="flex space-x-2">
              <Button variant="outline" size="sm">
                <RefreshCw className="w-4 h-4 mr-1" />
                Regenerate
              </Button>
              <Button variant="outline" size="sm">
                <Trash2 className="w-4 h-4" />
              </Button>
            </div>
          </div>
          <Button>
            <Key className="w-4 h-4 mr-2" />
            Generate New Key
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Session Management</CardTitle>
          <CardDescription>Manage your active sessions</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-green-50 border border-green-200 rounded-md">
              <div className="flex items-center space-x-3">
                <Monitor className="w-5 h-5 text-green-600" />
                <div>
                  <p className="font-medium">Current Session</p>
                  <p className="text-sm text-gray-600">Chrome on macOS • San Francisco, CA</p>
                  <p className="text-xs text-gray-500">Active now</p>
                </div>
              </div>
              <CheckCircle className="w-5 h-5 text-green-500" />
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-50 rounded-md">
              <div className="flex items-center space-x-3">
                <Smartphone className="w-5 h-5 text-gray-600" />
                <div>
                  <p className="font-medium">Mobile Session</p>
                  <p className="text-sm text-gray-600">Safari on iOS • San Francisco, CA</p>
                  <p className="text-xs text-gray-500">2 hours ago</p>
                </div>
              </div>
              <Button variant="outline" size="sm">
                <XCircle className="w-4 h-4 mr-1" />
                Revoke
              </Button>
            </div>
          </div>
          <Button variant="outline">
            <Trash2 className="w-4 h-4 mr-2" />
            Revoke All Other Sessions
          </Button>
        </CardContent>
      </Card>
    </div>
  )

  const renderNotificationSettings = () => (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Notification Preferences</CardTitle>
          <CardDescription>Choose how you want to be notified</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {notificationSettings.map((setting) => (
            <div key={setting.id} className="flex items-start justify-between p-4 border border-gray-200 rounded-md">
              <div className="flex-1">
                <div className="flex items-center space-x-2 mb-1">
                  <h4 className="font-medium">{setting.name}</h4>
                  <span className={`px-2 py-1 text-xs rounded-full ${
                    setting.enabled 
                      ? 'bg-green-100 text-green-700' 
                      : 'bg-gray-100 text-gray-700'
                  }`}>
                    {setting.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <p className="text-sm text-gray-600 mb-2">{setting.description}</p>
                <div className="flex space-x-2">
                  {setting.channels.map((channel) => (
                    <span key={channel} className="px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded-md">
                      {channel}
                    </span>
                  ))}
                </div>
              </div>
              <div className="flex space-x-2">
                <Button variant="outline" size="sm">
                  Configure
                </Button>
                <Button 
                  variant={setting.enabled ? 'outline' : 'default'} 
                  size="sm"
                >
                  {setting.enabled ? 'Disable' : 'Enable'}
                </Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )

  const renderAppearanceSettings = () => (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Theme Settings</CardTitle>
          <CardDescription>Customize the appearance of the interface</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              {darkMode ? <Moon className="w-5 h-5" /> : <Sun className="w-5 h-5" />}
              <div>
                <p className="font-medium">Dark Mode</p>
                <p className="text-sm text-gray-600">Use dark theme for the interface</p>
              </div>
            </div>
            <Button
              variant="outline"
              onClick={() => setDarkMode(!darkMode)}
            >
              {darkMode ? 'Disable' : 'Enable'}
            </Button>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              {soundEnabled ? <Volume2 className="w-5 h-5" /> : <VolumeX className="w-5 h-5" />}
              <div>
                <p className="font-medium">Sound Effects</p>
                <p className="text-sm text-gray-600">Play sounds for notifications and actions</p>
              </div>
            </div>
            <Button
              variant="outline"
              onClick={() => setSoundEnabled(!soundEnabled)}
            >
              {soundEnabled ? 'Disable' : 'Enable'}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Display Settings</CardTitle>
          <CardDescription>Configure display preferences</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Items per page
            </label>
            <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" defaultValue="25">
              <option value="10">10 items</option>
              <option value="25">25 items</option>
              <option value="50">50 items</option>
              <option value="100">100 items</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Date format
            </label>
            <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" defaultValue="YYYY-MM-DD">
              <option value="MM/DD/YYYY">MM/DD/YYYY</option>
              <option value="DD/MM/YYYY">DD/MM/YYYY</option>
              <option value="YYYY-MM-DD">YYYY-MM-DD</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Time format
            </label>
            <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" defaultValue="24h">
              <option value="12h">12-hour</option>
              <option value="24h">24-hour</option>
            </select>
          </div>
        </CardContent>
      </Card>
    </div>
  )

  const renderIntegrationsSettings = () => (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Connected Services</CardTitle>
          <CardDescription>Manage your external integrations</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {integrationServices.map((service) => (
            <div key={service.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-md">
              <div className="flex items-center space-x-3">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                  service.connected ? 'bg-green-100' : 'bg-gray-100'
                }`}>
                  <Globe className={`w-5 h-5 ${
                    service.connected ? 'text-green-600' : 'text-gray-600'
                  }`} />
                </div>
                <div>
                  <p className="font-medium">{service.name}</p>
                  <p className="text-sm text-gray-600">{service.description}</p>
                  {service.lastSync && (
                    <p className="text-xs text-gray-500">Last sync: {service.lastSync}</p>
                  )}
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <span className={`px-2 py-1 text-xs rounded-full ${
                  service.connected 
                    ? 'bg-green-100 text-green-700' 
                    : 'bg-gray-100 text-gray-700'
                }`}>
                  {service.connected ? 'Connected' : 'Disconnected'}
                </span>
                <Button variant="outline" size="sm">
                  {service.connected ? 'Configure' : 'Connect'}
                </Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )

  const renderSystemSettings = () => (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Scan Settings</CardTitle>
          <CardDescription>Configure automatic scanning behavior</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Zap className="w-5 h-5" />
              <div>
                <p className="font-medium">Automatic Scanning</p>
                <p className="text-sm text-gray-600">Run scans automatically on schedule</p>
              </div>
            </div>
            <Button
              variant="outline"
              onClick={() => setAutoScan(!autoScan)}
            >
              {autoScan ? 'Disable' : 'Enable'}
            </Button>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Scan frequency
            </label>
            <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" defaultValue="daily">
              <option value="hourly">Every hour</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Scan depth
            </label>
            <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" defaultValue="standard">
              <option value="quick">Quick scan</option>
              <option value="standard">Standard scan</option>
              <option value="deep">Deep scan</option>
            </select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Data Management</CardTitle>
          <CardDescription>Manage your data and backups</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Button variant="outline">
              <Download className="w-4 h-4 mr-2" />
              Export Data
            </Button>
            <Button variant="outline">
              <Upload className="w-4 h-4 mr-2" />
              Import Data
            </Button>
          </div>
          <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-md">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="w-5 h-5 text-yellow-600 mt-0.5" />
              <div>
                <p className="font-medium text-yellow-800">Data Retention</p>
                <p className="text-sm text-yellow-700">
                  Scan data is automatically deleted after 90 days. Export important data before it expires.
                </p>
              </div>
            </div>
          </div>
          <Button variant="outline" className="text-red-600 border-red-300 hover:bg-red-50">
            <Trash2 className="w-4 h-4 mr-2" />
            Delete All Data
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>System Information</CardTitle>
          <CardDescription>View system status and information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3 bg-gray-50 rounded-md">
              <p className="text-sm font-medium text-gray-600">Version</p>
              <p className="text-lg font-semibold">v2.1.0</p>
            </div>
            <div className="p-3 bg-gray-50 rounded-md">
              <p className="text-sm font-medium text-gray-600">Last Update</p>
              <p className="text-lg font-semibold">Oct 15, 2023</p>
            </div>
            <div className="p-3 bg-gray-50 rounded-md">
              <p className="text-sm font-medium text-gray-600">Database Size</p>
              <p className="text-lg font-semibold">2.4 GB</p>
            </div>
            <div className="p-3 bg-gray-50 rounded-md">
              <p className="text-sm font-medium text-gray-600">Active Scans</p>
              <p className="text-lg font-semibold">3</p>
            </div>
          </div>
          <Button variant="outline">
            <RefreshCw className="w-4 h-4 mr-2" />
            Check for Updates
          </Button>
        </CardContent>
      </Card>
    </div>
  )

  const renderContent = () => {
    switch (activeCategory) {
      case 'profile':
        return renderProfileSettings()
      case 'security':
        return renderSecuritySettings()
      case 'notifications':
        return renderNotificationSettings()
      case 'appearance':
        return renderAppearanceSettings()
      case 'integrations':
        return renderIntegrationsSettings()
      case 'system':
        return renderSystemSettings()
      default:
        return renderProfileSettings()
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
          <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
          <p className="text-gray-600">
            Manage your account settings and preferences
          </p>
        </div>
      </motion.div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Sidebar */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:w-64 flex-shrink-0"
        >
          <Card>
            <CardContent className="p-4">
              <nav className="space-y-1">
                {settingsCategories.map((category) => (
                  <button
                    key={category.id}
                    onClick={() => setActiveCategory(category.id)}
                    className={`w-full flex items-center space-x-3 px-3 py-2 text-left rounded-md transition-colors ${
                      activeCategory === category.id
                        ? 'bg-blue-100 text-blue-700'
                        : 'text-gray-700 hover:bg-gray-100'
                    }`}
                  >
                    <category.icon className="w-5 h-5" />
                    <div>
                      <p className="font-medium">{category.name}</p>
                      <p className="text-xs text-gray-500">{category.description}</p>
                    </div>
                  </button>
                ))}
              </nav>
            </CardContent>
          </Card>
        </motion.div>

        {/* Main Content */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="flex-1"
        >
          {renderContent()}
        </motion.div>
      </div>
    </div>
  )
}
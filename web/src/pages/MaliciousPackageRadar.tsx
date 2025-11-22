import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import { AlertTriangle, Shield, Globe, FileText, Activity, Users, Radar, TrendingUp, Filter, RefreshCw, Eye, ExternalLink } from 'lucide-react'
import { apiService, MaliciousPackage, Campaign } from '../services/api'
import { useNotifications } from '../contexts/NotificationContext'

export function MaliciousPackageRadar() {
  const [maliciousPackages, setMaliciousPackages] = useState<MaliciousPackage[]>([])
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [loading, setLoading] = useState(true)
  const [stats, setStats] = useState({
    totalMaliciousPackages: 0,
    activeCampaigns: 0,
    highRiskPackages: 0,
    quarantinedPackages: 0
  })
  const [selectedTab, setSelectedTab] = useState<'packages' | 'campaigns'>('packages')
  const [filters, setFilters] = useState({
    riskLevel: '',
    ecosystem: '',
    campaignId: '',
    status: ''
  })
  const { showError, success: showSuccess } = useNotifications()

  useEffect(() => {
    loadData()
  }, [filters])

  const loadData = async () => {
    try {
      setLoading(true)
      const [packagesData, campaignsData, statsData] = await Promise.all([
        apiService.getMaliciousPackages(filters),
        apiService.getCampaigns(filters),
        apiService.getMaliciousPackageStats()
      ])
      
      setMaliciousPackages(packagesData)
      setCampaigns(campaignsData)
      setStats(statsData)
    } catch (error) {
      console.error('Failed to load malicious package data:', error)
      showError(error instanceof Error ? error.message : 'Unknown error occurred')
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'critical': return 'text-red-600 bg-red-100'
      case 'high': return 'text-orange-600 bg-orange-100'
      case 'medium': return 'text-yellow-600 bg-yellow-100'
      case 'low': return 'text-green-600 bg-green-100'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  const getRiskBadgeVariant = (riskLevel: string) => {
    switch (riskLevel) {
      case 'critical': return 'destructive'
      case 'high': return 'destructive'
      case 'medium': return 'default'
      case 'low': return 'secondary'
      default: return 'secondary'
    }
  }

  const getEcosystemColor = (ecosystem: string) => {
    switch (ecosystem.toLowerCase()) {
      case 'npm': return 'text-red-600 bg-red-100'
      case 'pypi': return 'text-blue-600 bg-blue-100'
      case 'maven': return 'text-orange-600 bg-orange-100'
      case 'go': return 'text-cyan-600 bg-cyan-100'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString()
  }

  const refreshData = async () => {
    await loadData()
    showSuccess('Malicious package radar data has been updated')
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <Radar className="w-8 h-8 text-blue-600" />
            Malicious Package Radar
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Real-time detection and analysis of malicious packages across ecosystems
          </p>
        </div>
        <Button onClick={refreshData} disabled={loading}>
          <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Malicious Packages</CardTitle>
            <AlertTriangle className="w-4 h-4 text-red-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.totalMaliciousPackages}</div>
            <p className="text-xs text-gray-500">Across all ecosystems</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Campaigns</CardTitle>
            <Users className="w-4 h-4 text-purple-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-purple-600">{stats.activeCampaigns}</div>
            <p className="text-xs text-gray-500">Coordinated threats</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Risk Packages</CardTitle>
            <TrendingUp className="w-4 h-4 text-orange-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600">{stats.highRiskPackages}</div>
            <p className="text-xs text-gray-500">Critical & High severity</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Quarantined</CardTitle>
            <Shield className="w-4 h-4 text-green-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{stats.quarantinedPackages}</div>
            <p className="text-xs text-gray-500">Successfully blocked</p>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex space-x-8">
          <button
            onClick={() => setSelectedTab('packages')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              selectedTab === 'packages'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Malicious Packages ({maliciousPackages.length})
            </div>
          </button>
          <button
            onClick={() => setSelectedTab('campaigns')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              selectedTab === 'campaigns'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <div className="flex items-center gap-2">
              <Users className="w-4 h-4" />
              Threat Campaigns ({campaigns.length})
            </div>
          </button>
        </nav>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Filter className="w-5 h-5" />
            Filters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Risk Level
              </label>
              <select
                value={filters.riskLevel}
                onChange={(e) => setFilters({...filters, riskLevel: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="">All Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Ecosystem
              </label>
              <select
                value={filters.ecosystem}
                onChange={(e) => setFilters({...filters, ecosystem: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="">All Ecosystems</option>
                <option value="npm">NPM</option>
                <option value="pypi">PyPI</option>
                <option value="maven">Maven</option>
                <option value="go">Go</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Status
              </label>
              <select
                value={filters.status}
                onChange={(e) => setFilters({...filters, status: e.target.value})}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="">All Statuses</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
                <option value="quarantined">Quarantined</option>
              </select>
            </div>
            <div className="flex items-end">
              <Button
                onClick={() => setFilters({ riskLevel: '', ecosystem: '', campaignId: '', status: '' })}
                variant="outline"
              >
                Clear Filters
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Content */}
      {selectedTab === 'packages' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
          {maliciousPackages.map((pkg) => (
            <Card key={pkg.id} className="hover:shadow-lg transition-shadow">
              <CardHeader>
                <div className="flex justify-between items-start">
                  <div>
                    <CardTitle className="text-lg">{pkg.name}</CardTitle>
                    <CardDescription>{pkg.ecosystem} • v{pkg.version}</CardDescription>
                  </div>
                  <Badge variant={getRiskBadgeVariant(pkg.riskLevel)}>
                    {pkg.riskLevel.toUpperCase()}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600 dark:text-gray-400">Risk Score</span>
                  <span className="font-semibold">{pkg.riskScore.toFixed(1)}</span>
                </div>
                
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="flex items-center gap-1">
                    <FileText className="w-3 h-3 text-blue-600" />
                    <span>{pkg.behaviorSummary.filesystemActions} FS Actions</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Globe className="w-3 h-3 text-green-600" />
                    <span>{pkg.behaviorSummary.networkAttempts} Network</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Activity className="w-3 h-3 text-orange-600" />
                    <span>{pkg.behaviorSummary.suspiciousPatterns} Patterns</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Shield className="w-3 h-3 text-purple-600" />
                    <span>{pkg.behaviorSummary.processBehavior} Process</span>
                  </div>
                </div>

                {pkg.campaignName && (
                  <div className="flex items-center gap-2 text-sm">
                    <Users className="w-3 h-3 text-purple-600" />
                    <span className="text-purple-600 font-medium">{pkg.campaignName}</span>
                  </div>
                )}

                <div className="flex justify-between text-xs text-gray-500">
                  <span>First seen: {formatDate(pkg.firstSeen)}</span>
                  <span>Status: {pkg.status}</span>
                </div>

                <div className="flex gap-2">
                  <Button size="sm" variant="outline" className="flex-1">
                    <Eye className="w-3 h-3 mr-1" />
                    Details
                  </Button>
                  <Button size="sm" variant="outline">
                    <ExternalLink className="w-3 h-3" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {selectedTab === 'campaigns' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {campaigns.map((campaign) => (
            <Card key={campaign.id} className="hover:shadow-lg transition-shadow">
              <CardHeader>
                <div className="flex justify-between items-start">
                  <div>
                    <CardTitle className="text-lg">{campaign.name}</CardTitle>
                    <CardDescription>{campaign.description}</CardDescription>
                  </div>
                  <Badge variant={getRiskBadgeVariant(campaign.severity)}>
                    {campaign.severity.toUpperCase()}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-600 dark:text-gray-400">Ecosystem</span>
                    <p className="font-medium">{campaign.ecosystem}</p>
                  </div>
                  <div>
                    <span className="text-gray-600 dark:text-gray-400">Packages</span>
                    <p className="font-medium">{campaign.packageCount}</p>
                  </div>
                  <div>
                    <span className="text-gray-600 dark:text-gray-400">Risk Score</span>
                    <p className="font-medium">{campaign.riskScore.toFixed(1)}</p>
                  </div>
                  <div>
                    <span className="text-gray-600 dark:text-gray-400">Status</span>
                    <p className="font-medium capitalize">{campaign.status}</p>
                  </div>
                </div>

                <div>
                  <span className="text-gray-600 dark:text-gray-400 text-sm">Affected Ecosystems</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {campaign.affectedEcosystems.map((eco) => (
                      <Badge key={eco} variant="outline" className="text-xs">
                        {eco}
                      </Badge>
                    ))}
                  </div>
                </div>

                <div className="flex justify-between text-xs text-gray-500">
                  <span>First seen: {formatDate(campaign.firstSeen)}</span>
                  <span>Last seen: {formatDate(campaign.lastSeen)}</span>
                </div>

                <div className="flex gap-2">
                  <Button size="sm" variant="outline" className="flex-1">
                    <Eye className="w-3 h-3 mr-1" />
                    View Details
                  </Button>
                  <Button size="sm" variant="outline">
                    <ExternalLink className="w-3 h-3" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {loading && (
        <div className="flex justify-center items-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <span className="ml-3 text-gray-600 dark:text-gray-400">Loading malicious package data...</span>
        </div>
      )}

      {!loading && maliciousPackages.length === 0 && campaigns.length === 0 && (
        <Card>
          <CardContent className="text-center py-12">
            <Radar className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              No malicious packages detected
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              Your supply chain is clean! Continue monitoring to detect future threats.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
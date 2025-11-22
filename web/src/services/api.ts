// API Service for Typosentinel Web Application
// This service handles all API calls to the backend

export interface ScanResult {
  id: string
  name: string
  target: string
  status: 'running' | 'completed' | 'failed' | 'pending'
  vulnerabilities: number
  lastRun: string
  duration: string
  progress: number
  details?: VulnerabilityDetail[]
}

export interface VulnerabilityDetail {
  id: string
  title: string
  package: string
  version: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  score: number
  description: string
  publishedDate: string
  lastModified: string
  status: 'open' | 'fixed' | 'investigating'
  affectedVersions: string
  fixedVersion?: string
  proposedCorrection?: string
  cve?: string
  references: string[]
}

export interface Report {
  id: string
  title: string
  type: 'security' | 'dependencies' | 'compliance' | 'analytics' | 'executive'
  description: string
  generatedDate: string
  status: 'completed' | 'generating' | 'failed'
  format: string
  size: string
  author: string
  tags: string[]
  downloadUrl?: string
}

export interface SystemStatus {
  scannerEngine: 'online' | 'offline' | 'degraded'
  database: 'connected' | 'disconnected' | 'degraded'
  apiGateway: 'online' | 'offline' | 'degraded'
}

export interface DashboardStats {
  totalScans: number
  vulnerabilitiesFound: number
  packagesSecured: number
  activeMonitors: number
  // Additional fields from backend
  packagesScanned?: number
  threatsDetected?: number
  criticalThreats?: number
  scanSuccessRate?: number
  averageScanTime?: number
}

export interface Integration {
  id: string
  name: string
  description: string
  status: 'connected' | 'disconnected' | 'error'
  category: string
  features: string[]
  icon: string
  lastSync?: string
}

export interface IntegrationStatus {
  id: string
  status: 'connected' | 'disconnected' | 'error'
  lastCheck: string
  healthy: boolean
  lastSync?: string
  syncCount: number
  errorCount: number
}

export interface IntegrationActivity {
  id: string
  type: string
  status: 'success' | 'error' | 'pending'
  timestamp: string
  message: string
  details?: Record<string, any>
}

export interface MaliciousPackage {
  id: string
  name: string
  ecosystem: string
  version: string
  riskScore: number
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  behaviorScore: number
  campaignScore: number
  baseScore: number
  threats: Array<{
    type: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    description: string
    confidence: number
  }>
  behaviorSummary: {
    filesystemActions: number
    networkAttempts: number
    suspiciousPatterns: number
    processBehavior: number
  }
  campaignId?: string
  campaignName?: string
  firstSeen: string
  lastSeen: string
  status: 'active' | 'inactive' | 'quarantined'
}

export interface Campaign {
  id: string
  name: string
  description: string
  ecosystem: string
  packageCount: number
  affectedEcosystems: string[]
  severity: 'low' | 'medium' | 'high' | 'critical'
  riskScore: number
  firstSeen: string
  lastSeen: string
  status: 'active' | 'inactive' | 'mitigated'
  packages: Array<{
    name: string
    version: string
    ecosystem: string
    riskScore: number
  }>
  indicators: Array<{
    type: string
    description: string
    confidence: number
  }>
  networkIOCs: string[]
  fileIOCs: string[]
  authorSignatures: Array<{
    name: string
    email: string
    confidence: number
  }>
}

export interface BehaviorProfile {
  packageId: string
  packageName: string
  ecosystem: string
  filesystemActions: Array<{
    action: string
    path: string
    timestamp: string
    risk: 'low' | 'medium' | 'high' | 'critical'
  }>
  networkAttempts: Array<{
    domain: string
    ip: string
    port: number
    protocol: string
    timestamp: string
    risk: 'low' | 'medium' | 'high' | 'critical'
  }>
  suspiciousPatterns: Array<{
    pattern: string
    description: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    confidence: number
  }>
  processBehavior: Array<{
    action: string
    target: string
    timestamp: string
    risk: 'low' | 'medium' | 'high' | 'critical'
  }>
  riskAssessment: {
    overallScore: number
    confidence: number
    riskLevel: 'low' | 'medium' | 'high' | 'critical'
  }
}

export interface DatabaseInstance {
  id: string
  name: string
  type: string
  version: string
  status: 'healthy' | 'warning' | 'error'
  size: string
  connections: number
  maxConnections: number
  uptime: string
  lastBackup: string
  vulnerabilities: number
  securityScore: number
}

export interface DatabaseActivity {
  id: number
  type: string
  database: string
  action: string
  timestamp: string
  status: 'success' | 'warning' | 'error' | 'info'
  details: string
}

export interface DatabaseSecurityCheck {
  name: string
  status: 'enabled' | 'disabled' | 'warning'
  description: string
}

export interface PerformanceMetrics {
  response_times: {
    api: number
    dashboard: number
    scanner: number
  }
  throughput: {
    api_requests_per_sec: number
    scans_per_hour: number
  }
  error_rates: {
    api: number
    scanner: number
  }
  resource_metrics: {
    cpu_usage: number
    memory_usage: number
    disk_usage: number
    network_io: number
    open_files: number
    goroutines: number
  }
  performance_trends: any[]
}

class ApiService {
  private baseUrl: string

  constructor() {
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:3000'
    // If VITE_API_URL is just a path like '/api', use it as is
    // If it's a full URL, use it as is
    this.baseUrl = apiUrl
  }

  // Generic API call method
  private async apiCall<T>(endpoint: string, options: RequestInit = {}, retries = 3): Promise<T> {
    // If baseUrl is just a path (like '/api'), construct the full URL
     // If endpoint already starts with '/api' and baseUrl is '/api', avoid duplication
     let url: string
     if (this.baseUrl.startsWith('/') && endpoint.startsWith('/api') && this.baseUrl === '/api') {
       url = endpoint // Use endpoint as is since it already includes /api
     } else {
       url = `${this.baseUrl}${endpoint}`
     }

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const controller = new AbortController()
        const timeoutId = setTimeout(() => controller.abort(), 30000) // 30 second timeout

        const response = await fetch(url, {
          headers: {
            'Content-Type': 'application/json',
            ...options.headers,
          },
          signal: controller.signal,
          ...options,
        })

        clearTimeout(timeoutId)

        if (!response.ok) {
          const errorData = await response.text().catch(() => 'Unknown error')
          
          // Handle different HTTP status codes
          switch (response.status) {
            case 400:
              throw new Error(`Bad Request: ${errorData}`)
            case 401:
              throw new Error('Unauthorized: Please check your authentication')
            case 403:
              throw new Error('Forbidden: You do not have permission to access this resource')
            case 404:
              throw new Error(`Not Found: The requested resource was not found (${endpoint})`)
            case 429:
              throw new Error('Too Many Requests: Please try again later')
            case 500:
              throw new Error('Internal Server Error: The server encountered an error')
            case 502:
              throw new Error('Bad Gateway: The server is temporarily unavailable')
            case 503:
              throw new Error('Service Unavailable: The server is temporarily unavailable')
            default:
              throw new Error(`API call failed (${response.status}): ${response.statusText}`)
          }
        }

        const contentType = response.headers.get('content-type')
        if (contentType && contentType.includes('application/json')) {
          return await response.json()
        } else {
          // Handle non-JSON responses
          const text = await response.text()
          return text as unknown as T
        }
      } catch (error) {
        const isLastAttempt = attempt === retries
        
        if (error instanceof Error) {
          // Network errors or timeout
          if (error.name === 'AbortError') {
            console.error(`API call timeout for ${endpoint} (attempt ${attempt + 1}/${retries + 1})`)
            if (isLastAttempt) {
              throw new Error(`Request timeout: The server took too long to respond for ${endpoint}`)
            }
          } else if (error.message.includes('fetch')) {
            console.error(`Network error for ${endpoint} (attempt ${attempt + 1}/${retries + 1}):`, error.message)
            if (isLastAttempt) {
              throw new Error(`Network error: Unable to connect to the server. Please check your internet connection.`)
            }
          } else {
            // HTTP errors or other API errors - don't retry
            console.error(`API error for ${endpoint}:`, error.message)
            throw error
          }
        } else {
          console.error(`Unknown error for ${endpoint}:`, error)
          if (isLastAttempt) {
            throw new Error(`Unknown error occurred while calling ${endpoint}`)
          }
        }

        // Wait before retrying (exponential backoff)
        if (!isLastAttempt) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 5000) // Max 5 second delay
          await new Promise(resolve => setTimeout(resolve, delay))
        }
      }
    }

    // This should never be reached, but TypeScript requires it
    throw new Error(`Failed to complete API call to ${endpoint} after ${retries + 1} attempts`)
  }



  // Dashboard API methods
  async getDashboardStats(): Promise<DashboardStats> {
    try {
      // Use the correct dashboard metrics endpoint
      const response = await this.apiCall<{
        totalScans: number
        threatsDetected: number
        criticalThreats: number
        packagesScanned: number
        scanSuccessRate: number
        averageScanTime: number
        timeRange: string
        lastUpdated: string
      }>('/api/v1/dashboard/metrics')
      
      return {
        totalScans: response.totalScans || 0,
        vulnerabilitiesFound: response.threatsDetected || 0,
        packagesSecured: response.packagesScanned || 0,
        activeMonitors: 8, // This would need a separate endpoint
        // Include additional backend fields
        packagesScanned: response.packagesScanned || 0,
        threatsDetected: response.threatsDetected || 0,
        criticalThreats: response.criticalThreats || 0,
        scanSuccessRate: response.scanSuccessRate || 0,
        averageScanTime: response.averageScanTime || 0
      }
    } catch (error) {
      console.error('Failed to get dashboard stats:', error)
      // Return default values if API calls fail
      return {
        totalScans: 0,
        vulnerabilitiesFound: 0,
        packagesSecured: 0,
        activeMonitors: 0,
        packagesScanned: 0,
        threatsDetected: 0,
        criticalThreats: 0,
        scanSuccessRate: 0,
        averageScanTime: 0
      }
    }
  }

  async getSystemStatus(): Promise<SystemStatus> {
    try {
      // Check if the performance endpoint is working to determine system status
      await this.apiCall<PerformanceMetrics>('/api/v1/dashboard/performance')
      return {
        scannerEngine: 'online',
        database: 'connected',
        apiGateway: 'online'
      }
    } catch (error) {
      console.error('System status check failed:', error)
      return {
        scannerEngine: 'offline',
        database: 'disconnected',
        apiGateway: 'offline'
      }
    }
  }

  async getRecentScans(): Promise<ScanResult[]> {
    try {
      // Use the actual scan results endpoint
      const response = await this.apiCall<{data: any[], pagination: any}>('/api/scan/results?limit=5')
      // Convert scan results to frontend format
      return response.data.map(scan => ({
        id: scan.id,
        name: scan.target || `scan-${scan.id}`,
        target: scan.target,
        status: scan.status as 'running' | 'completed' | 'failed' | 'pending',
        vulnerabilities: scan.threatsFound || 0,
        lastRun: scan.createdAt,
        duration: scan.duration || '0s',
        progress: scan.status === 'completed' ? 100 : (scan.status === 'running' ? 50 : 0)
      }))
    } catch (error) {
      console.error('Failed to get recent scans:', error)
      // Return empty array if API call fails
      return []
    }
  }

  // Security Scans API methods
  async getAllScans(): Promise<ScanResult[]> {
    try {
      const response = await this.apiCall<{data: any[], pagination: any}>('/api/scan/results')
      // Convert scan results to frontend format
      return response.data.map(scan => ({
        id: scan.id,
        name: scan.target,
        target: scan.target,
        status: scan.status as 'running' | 'completed' | 'failed' | 'pending',
        vulnerabilities: scan.threatsFound || 0,
        lastRun: scan.createdAt,
        duration: scan.duration || '0s',
        progress: scan.status === 'completed' ? 100 : 0
      }))
    } catch (error) {
      console.error('Failed to get all scans:', error)
      return []
    }
  }

  async getScanDetails(scanId: string): Promise<ScanResult> {
    return this.apiCall<ScanResult>(`/scan/${scanId}`)
  }

  async runScan(_scanId: string): Promise<{ success: boolean; message: string }> {
    // Backend doesn't support running existing scans, return mock response
    return Promise.resolve({ success: false, message: 'Running existing scans is not supported. Please create a new scan.' })
  }

  async pauseScan(_scanId: string): Promise<{ success: boolean; message: string }> {
    // Backend doesn't support pausing scans, return mock response
    return Promise.resolve({ success: false, message: 'Pausing scans is not supported.' })
  }

  async createNewScan(scanConfig: {
    name: string
    target: string
    type: string
  }): Promise<{ success: boolean; scanId: string; message: string }> {
    return this.apiCall('/api/scan/start', {
      method: 'POST',
      body: JSON.stringify(scanConfig),
    })
  }

  // Reports API methods
  async getAllReports(): Promise<Report[]> {
    const response = await this.apiCall<{ reports: Report[] }>('/api/reports')
    return response.reports
  }

  async generateReport(reportConfig: {
    type: string
    title: string
    description?: string
    format?: string
  }): Promise<{ success: boolean; reportId: string; message: string; estimatedTime: string }> {
    return this.apiCall('/api/reports/generate', {
      method: 'POST',
      body: JSON.stringify(reportConfig),
    })
  }

  async downloadReport(reportId: string): Promise<Blob> {
    const response = await fetch(`${this.baseUrl}/api/reports/${reportId}/download`)
    if (!response.ok) {
      throw new Error('Failed to download report')
    }
    return response.blob()
  }

  async getReportTemplates(): Promise<Array<{
    id: string
    name: string
    description: string
    type: string
    format: string
    icon: string
    color: string
  }>> {
    return this.apiCall('/api/reports/templates')
  }

  async scheduleReport(scheduleConfig: {
    reportType: string
    frequency: string
    recipients: string[]
  }): Promise<{ success: boolean; scheduleId: string; message: string }> {
    return this.apiCall('/api/reports/schedule', {
      method: 'POST',
      body: JSON.stringify(scheduleConfig),
    })
  }

  // Database API methods
  async updateDatabase(): Promise<{ success: boolean; message: string }> {
    return this.apiCall('/api/database/update', { method: 'POST' })
  }

  async getDatabaseStatus(): Promise<{
    lastUpdate: string
    version: string
    recordCount: number
    status: string
  }> {
    return this.apiCall('/api/database/status')
  }

  async getAllDatabases(): Promise<{ databases: DatabaseInstance[] }> {
    return this.apiCall('/api/database/list')
  }

  async getDatabaseInstanceStatus(databaseId: string): Promise<{
    id: string
    status: string
    connections: number
    maxConnections: number
    cpuUsage: number
    memoryUsage: number
    diskUsage: number
    lastCheck: string
    performanceMetrics?: {
      queriesPerSec: number
      avgQueryTime: number
      cacheHitRate: number
    }
    cacheMetrics?: {
      cacheSize: string
      cacheUsed: string
      cacheUtilization: number
      cacheEvictions: number
      cacheHits: number
      cacheMisses: number
      hitRate: number
      totalHits: number
      totalReads: number
      missRate: number
    }
  }> {
    return this.apiCall(`/api/database/${databaseId}/status`)
  }

  async getDatabaseRecentQueries(databaseId: string, limit: number = 10): Promise<{
    queries: Array<{
      query: string
      duration: string
      calls: number
      totalTime: string
      timestamp: string
    }>
  }> {
    return this.apiCall(`/api/database/${databaseId}/queries?limit=${limit}`)
  }

  async getDatabaseActivity(): Promise<{ activities: DatabaseActivity[] }> {
    return this.apiCall('/api/database/activity')
  }

  async getDatabaseSecurity(): Promise<{ securityChecks: DatabaseSecurityCheck[] }> {
    return this.apiCall('/api/database/security')
  }

  // Team management API methods
  async getTeamMembers(): Promise<any[]> {
    return this.apiCall('/team/members')
  }

  async inviteTeamMember(email: string, role: string): Promise<{ success: boolean; message: string }> {
    return this.apiCall('/team/invite', {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    })
  }

  // Vulnerabilities API methods
  async getVulnerabilities(filters?: {
    severity?: string
    status?: string
    package?: string
  }): Promise<VulnerabilityDetail[]> {
    const queryParams = new URLSearchParams()
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value) queryParams.append(key, value)
      })
    }
    const endpoint = `/api/v1/vulnerabilities${queryParams.toString() ? '?' + queryParams.toString() : ''}`
    return this.apiCall<VulnerabilityDetail[]>(endpoint)
  }

  async markVulnerabilityResolved(vulnId: string): Promise<{ success: boolean; message: string }> {
    return this.apiCall(`/api/v1/vulnerabilities/${vulnId}/resolve`, { method: 'POST' })
  }

  // Analytics API methods
  async getAnalytics(timeRange: string = '7d'): Promise<{
    scanTrends: Array<{ date: string; scans: number; vulnerabilities: number }>
    severityDistribution: Array<{ severity: string; count: number }>
    topVulnerablePackages: Array<{ package: string; vulnerabilities: number }>
    summary?: {
      totalVulnerabilities: number
      securityScore: number
      scansPerformed: number
      avgResponseTime: number
    }
  }> {
    return this.apiCall(`/api/analytics?range=${timeRange}`)
  }

  async getPerformance(): Promise<PerformanceMetrics> {
    return this.apiCall('/api/v1/dashboard/performance')
  }

  // Malicious Package Radar API methods
  async getMaliciousPackages(filters?: {
    riskLevel?: string
    ecosystem?: string
    campaignId?: string
    status?: string
    limit?: number
  }): Promise<MaliciousPackage[]> {
    const queryParams = new URLSearchParams()
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value) queryParams.append(key, value.toString())
      })
    }
    const endpoint = `/api/v1/malicious-packages${queryParams.toString() ? '?' + queryParams.toString() : ''}`
    const response = await this.apiCall<{packages: MaliciousPackage[]}>(endpoint)
    return response.packages || []
  }

  async getCampaigns(filters?: {
    severity?: string
    ecosystem?: string
    status?: string
    limit?: number
  }): Promise<Campaign[]> {
    const queryParams = new URLSearchParams()
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value) queryParams.append(key, value.toString())
      })
    }
    const endpoint = `/api/v1/campaigns${queryParams.toString() ? '?' + queryParams.toString() : ''}`
    const response = await this.apiCall<{campaigns: Campaign[]}>(endpoint)
    return response.campaigns || []
  }

  async getCampaignDetails(campaignId: string): Promise<Campaign> {
    return this.apiCall(`/api/v1/campaigns/${campaignId}`)
  }

  async getBehaviorProfile(packageId: string): Promise<BehaviorProfile> {
    return this.apiCall(`/api/v1/behavior-profiles/${packageId}`)
  }

  async getMaliciousPackageStats(): Promise<{
    totalMaliciousPackages: number
    activeCampaigns: number
    highRiskPackages: number
    quarantinedPackages: number
    topThreatTypes: Array<{type: string; count: number}>
    ecosystemDistribution: Array<{ecosystem: string; count: number}>
  }> {
    return this.apiCall('/api/v1/malicious-packages/stats')
  }

  // Real backend analysis methods
  async analyzePackage(packageName: string): Promise<{
    package_name: string
    registry: string
    threats: Array<{
      type: string
      severity: string
      description: string
      confidence: number
    }>
    warnings: Array<{
      type: string
      description: string
    }>
    risk_level: number
    risk_score: number
    analyzed_at: string
  }> {
    return this.apiCall('/api/v1/analyze', {
      method: 'POST',
      body: JSON.stringify({ 
        package_name: packageName,
        registry: 'npm'
      }),
    })
  }

  async getBackendStatus(): Promise<{
    service: string
    status: string
    version: string
    features: Record<string, boolean>
    limits: Record<string, number>
  }> {
    return this.apiCall('/api/v1/status')
  }

  // Integration methods
  async getAllIntegrations(): Promise<Integration[]> {
    const response = await this.apiCall<{integrations: Integration[]}>('/api/integrations')
    return response.integrations || []
  }

  async connectIntegration(integrationId: string, config?: Record<string, any>): Promise<{
    success: boolean
    message: string
    status: string
  }> {
    return this.apiCall(`/api/integrations/${integrationId}/connect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config || {})
    })
  }

  async disconnectIntegration(integrationId: string): Promise<{
    success: boolean
    message: string
    status: string
  }> {
    return this.apiCall(`/api/integrations/${integrationId}/disconnect`, {
      method: 'POST'
    })
  }

  async getIntegrationStatus(integrationId: string): Promise<IntegrationStatus> {
    return this.apiCall(`/api/integrations/${integrationId}/status`)
  }

  async configureIntegration(integrationId: string, config: Record<string, any>): Promise<{
    success: boolean
    message: string
    config: Record<string, any>
  }> {
    return this.apiCall(`/api/integrations/${integrationId}/configure`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    })
  }

  async getIntegrationActivity(integrationId: string): Promise<{
    integrationId: string
    activities: IntegrationActivity[]
    pagination: {
      page: number
      pageSize: number
      total: number
      hasMore: boolean
    }
  }> {
    return this.apiCall(`/api/integrations/${integrationId}/activity`)
  }
}

// Export singleton instance
export const apiService = new ApiService()
export default apiService
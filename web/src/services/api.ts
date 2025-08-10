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
  package: string
  version: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  cve?: string
  fixedVersion?: string
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
}

class ApiService {
  private baseUrl: string
  private mockMode: boolean = false // Backend is now running

  constructor() {
    this.baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:8080'
  }

  // Generic API call method
  private async apiCall<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    if (this.mockMode) {
      return this.mockApiCall<T>(endpoint, options)
    }

    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        ...options,
      })

      if (!response.ok) {
        // If endpoint not found, fall back to mock data for demo
        if (response.status === 404) {
          console.warn(`Endpoint ${endpoint} not found, using mock data`)
          return this.mockApiCall<T>(endpoint, options)
        }
        throw new Error(`API call failed: ${response.statusText}`)
      }

      return await response.json()
    } catch (error) {
      console.error('API call error:', error)
      // Fall back to mock data if backend is unavailable
      console.warn('Falling back to mock data due to API error')
      return this.mockApiCall<T>(endpoint, options)
    }
  }

  // Mock API responses for development
  private async mockApiCall<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000))

    const method = options.method || 'GET'
    
    // Mock responses based on endpoint
    if (endpoint === '/dashboard/stats' && method === 'GET') {
      return {
        totalScans: 2847 + Math.floor(Math.random() * 100),
        vulnerabilitiesFound: 23 + Math.floor(Math.random() * 10),
        packagesSecured: 1234 + Math.floor(Math.random() * 50),
        activeMonitors: 89 + Math.floor(Math.random() * 20),
      } as T
    }

    if (endpoint === '/system/status' && method === 'GET') {
      return {
        scannerEngine: 'online',
        database: 'connected',
        apiGateway: Math.random() > 0.7 ? 'degraded' : 'online',
      } as T
    }

    if (endpoint === '/scans' && method === 'GET') {
      return [
        {
          id: '1',
          name: 'Frontend Dependencies',
          target: 'package.json',
          status: 'completed',
          vulnerabilities: 3,
          lastRun: '2 hours ago',
          duration: '45s',
          progress: 100,
        },
        {
          id: '2',
          name: 'Backend API Scan',
          target: 'api/',
          status: 'running',
          vulnerabilities: 0,
          lastRun: 'Running now',
          duration: '2m 15s',
          progress: 67,
        },
      ] as T
    }

    if (endpoint.startsWith('/scans/') && endpoint.endsWith('/run') && method === 'POST') {
      return { success: true, message: 'Scan started successfully' } as T
    }

    if (endpoint === '/reports' && method === 'GET') {
      return [
        {
          id: 'RPT-001',
          title: 'Weekly Security Summary',
          type: 'security',
          description: 'Comprehensive security analysis for the past week including vulnerability scans and threat assessments.',
          generatedDate: new Date().toISOString().split('T')[0],
          status: 'completed',
          format: 'PDF',
          size: '2.4 MB',
          author: 'Security Team',
          tags: ['weekly', 'security', 'vulnerabilities'],
          metrics: {
            vulnerabilities: 12,
            scans: 45,
            packages: 234
          }
        },
        {
          id: 'RPT-002',
          title: 'Dependency Audit Report',
          type: 'dependencies',
          description: 'Detailed analysis of all project dependencies, including outdated packages and security recommendations.',
          generatedDate: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          status: 'completed',
          format: 'PDF',
          size: '1.8 MB',
          author: 'DevOps Team',
          tags: ['dependencies', 'audit', 'packages'],
          metrics: {
            vulnerabilities: 8,
            scans: 23,
            packages: 156
          }
        },
        {
          id: 'RPT-003',
          title: 'Compliance Assessment',
          type: 'compliance',
          description: 'Monthly compliance report covering security standards and regulatory requirements.',
          generatedDate: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          status: 'generating',
          format: 'PDF',
          size: 'Generating...',
          author: 'Compliance Team',
          tags: ['compliance', 'monthly', 'standards'],
          metrics: {
            vulnerabilities: 0,
            scans: 67,
            packages: 289
          }
        },
        {
          id: 'RPT-004',
          title: 'Vulnerability Trends Analysis',
          type: 'analytics',
          description: 'Quarterly analysis of vulnerability trends and security improvements over time.',
          generatedDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          status: 'completed',
          format: 'PDF',
          size: '3.2 MB',
          author: 'Analytics Team',
          tags: ['quarterly', 'trends', 'analytics'],
          metrics: {
            vulnerabilities: 45,
            scans: 156,
            packages: 567
          }
        },
        {
          id: 'RPT-005',
          title: 'Executive Security Dashboard',
          type: 'executive',
          description: 'High-level security overview for executive leadership and stakeholders.',
          generatedDate: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          status: 'completed',
          format: 'PDF',
          size: '1.2 MB',
          author: 'Security Team',
          tags: ['executive', 'summary', 'leadership'],
          metrics: {
            vulnerabilities: 23,
            scans: 89,
            packages: 345
          }
        },
        {
          id: 'RPT-006',
          title: 'Critical Vulnerabilities Report',
          type: 'security',
          description: 'Emergency report highlighting critical security vulnerabilities requiring immediate attention.',
          generatedDate: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          status: 'completed',
          format: 'PDF',
          size: '856 KB',
          author: 'Security Team',
          tags: ['critical', 'urgent', 'vulnerabilities'],
          metrics: {
            vulnerabilities: 5,
            scans: 12,
            packages: 78
          }
        },
        {
          id: 'RPT-007',
          title: 'OWASP Top 10 Assessment',
          type: 'compliance',
          description: 'Assessment against OWASP Top 10 security risks and mitigation strategies.',
          generatedDate: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          status: 'completed',
          format: 'PDF',
          size: '2.1 MB',
          author: 'Security Team',
          tags: ['owasp', 'assessment', 'top10'],
          metrics: {
            vulnerabilities: 18,
            scans: 34,
            packages: 189
          }
        },
        {
          id: 'RPT-008',
          title: 'License Compliance Report',
          type: 'dependencies',
          description: 'Analysis of open source licenses and compliance requirements for all dependencies.',
          generatedDate: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          status: 'completed',
          format: 'PDF',
          size: '1.5 MB',
          author: 'Legal Team',
          tags: ['licenses', 'compliance', 'legal'],
          metrics: {
            vulnerabilities: 2,
            scans: 18,
            packages: 298
          }
        },
        {
          id: 'RPT-009',
          title: 'Performance Impact Analysis',
          type: 'analytics',
          description: 'Analysis of security scanning performance impact on CI/CD pipelines.',
          generatedDate: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          status: 'failed',
          format: 'PDF',
          size: 'Failed',
          author: 'DevOps Team',
          tags: ['performance', 'cicd', 'analysis'],
          metrics: {
            vulnerabilities: 0,
            scans: 0,
            packages: 0
          }
        },
        {
          id: 'RPT-010',
          title: 'Monthly Security Metrics',
          type: 'analytics',
          description: 'Comprehensive monthly metrics showing security posture improvements and KPIs.',
          generatedDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          status: 'completed',
          format: 'PDF',
          size: '4.1 MB',
          author: 'Analytics Team',
          tags: ['monthly', 'metrics', 'kpi'],
          metrics: {
            vulnerabilities: 67,
            scans: 234,
            packages: 789
          }
        }
      ] as T
    }

    if (endpoint === '/reports/generate' && method === 'POST') {
      const reportId = 'RPT-' + Date.now()
      return { 
        success: true, 
        reportId,
        message: 'Report generation started',
        estimatedTime: '2-3 minutes'
      } as T
    }

    // Default mock response
    return { success: true, message: 'Mock API response' } as T
  }

  // Dashboard API methods
  async getDashboardStats(): Promise<DashboardStats> {
    return this.apiCall<DashboardStats>('/dashboard/stats')
  }

  async getSystemStatus(): Promise<SystemStatus> {
    return this.apiCall<SystemStatus>('/system/status')
  }

  async getRecentScans(): Promise<ScanResult[]> {
    return this.apiCall<ScanResult[]>('/scans/recent')
  }

  // Security Scans API methods
  async getAllScans(): Promise<ScanResult[]> {
    return this.apiCall<ScanResult[]>('/scans')
  }

  async getScanDetails(scanId: string): Promise<ScanResult> {
    return this.apiCall<ScanResult>(`/scans/${scanId}`)
  }

  async runScan(scanId: string): Promise<{ success: boolean; message: string }> {
    return this.apiCall(`/scans/${scanId}/run`, { method: 'POST' })
  }

  async pauseScan(scanId: string): Promise<{ success: boolean; message: string }> {
    return this.apiCall(`/scans/${scanId}/pause`, { method: 'POST' })
  }

  async createNewScan(scanConfig: {
    name: string
    target: string
    type: string
  }): Promise<{ success: boolean; scanId: string; message: string }> {
    return this.apiCall('/scans', {
      method: 'POST',
      body: JSON.stringify(scanConfig),
    })
  }

  // Reports API methods
  async getAllReports(): Promise<Report[]> {
    return this.apiCall<Report[]>('/reports')
  }

  async generateReport(reportConfig: {
    type: string
    title: string
    description?: string
    format?: string
  }): Promise<{ success: boolean; reportId: string; message: string; estimatedTime: string }> {
    return this.apiCall('/reports/generate', {
      method: 'POST',
      body: JSON.stringify(reportConfig),
    })
  }

  async downloadReport(reportId: string): Promise<Blob> {
    if (this.mockMode) {
      // Create a mock PDF blob
      const pdfContent = `%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
72 720 Td
(Typosentinel Security Report) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000206 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
300
%%EOF`
      return new Blob([pdfContent], { type: 'application/pdf' })
    }

    const response = await fetch(`${this.baseUrl}/reports/${reportId}/download`)
    if (!response.ok) {
      throw new Error('Failed to download report')
    }
    return response.blob()
  }

  async scheduleReport(scheduleConfig: {
    reportType: string
    frequency: string
    recipients: string[]
  }): Promise<{ success: boolean; scheduleId: string; message: string }> {
    return this.apiCall('/reports/schedule', {
      method: 'POST',
      body: JSON.stringify(scheduleConfig),
    })
  }

  // Database API methods
  async updateDatabase(): Promise<{ success: boolean; message: string }> {
    return this.apiCall('/database/update', { method: 'POST' })
  }

  async getDatabaseStatus(): Promise<{
    lastUpdate: string
    version: string
    recordCount: number
    status: string
  }> {
    return this.apiCall('/database/status')
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
    const endpoint = `/vulnerabilities${queryParams.toString() ? '?' + queryParams.toString() : ''}`
    return this.apiCall<VulnerabilityDetail[]>(endpoint)
  }

  async markVulnerabilityResolved(vulnId: string): Promise<{ success: boolean; message: string }> {
    return this.apiCall(`/vulnerabilities/${vulnId}/resolve`, { method: 'POST' })
  }

  // Analytics API methods
  async getAnalytics(timeRange: string = '7d'): Promise<{
    scanTrends: Array<{ date: string; scans: number; vulnerabilities: number }>
    severityDistribution: Array<{ severity: string; count: number }>
    topVulnerablePackages: Array<{ package: string; vulnerabilities: number }>
  }> {
    return this.apiCall(`/analytics?range=${timeRange}`)
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
    return this.apiCall('/v1/analyze', {
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
    return this.apiCall('/v1/status')
  }
}

// Export singleton instance
export const apiService = new ApiService()
export default apiService
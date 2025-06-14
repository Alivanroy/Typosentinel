import { api } from './api'
import type {
  Package,
  ScanRequest,
  ScanResult,
  ProjectScan,
  DependencyTree,
} from '@/types/package'

interface PackageListParams {
  page?: number
  limit?: number
  search?: string
  registry?: string
  riskLevel?: string
  sortBy?: string
  sortOrder?: 'asc' | 'desc'
}

interface PackageListResponse {
  packages: Package[]
  total: number
  page: number
  limit: number
  totalPages: number
}

interface ScanListParams {
  page?: number
  limit?: number
  status?: string
  type?: string
  sortBy?: string
  sortOrder?: 'asc' | 'desc'
}

interface ScanListResponse {
  scans: ScanResult[]
  total: number
  page: number
  limit: number
  totalPages: number
}

class PackageService {
  // Package operations
  async getPackages(params: PackageListParams = {}): Promise<PackageListResponse> {
    const response = await api.get<PackageListResponse>('/packages', { params })
    return response.data
  }

  async getPackage(id: string): Promise<Package> {
    const response = await api.get<Package>(`/packages/${id}`)
    return response.data
  }

  async searchPackages(query: string, registry?: string): Promise<Package[]> {
    const response = await api.get<Package[]>('/packages/search', {
      params: { q: query, registry },
    })
    return response.data
  }

  async getPackageDependencies(id: string): Promise<DependencyTree> {
    const response = await api.get<DependencyTree>(`/packages/${id}/dependencies`)
    return response.data
  }

  async addToWhitelist(packageId: string): Promise<void> {
    await api.post(`/packages/${packageId}/whitelist`)
  }

  async removeFromWhitelist(packageId: string): Promise<void> {
    await api.delete(`/packages/${packageId}/whitelist`)
  }

  async addToBlacklist(packageId: string): Promise<void> {
    await api.post(`/packages/${packageId}/blacklist`)
  }

  async removeFromBlacklist(packageId: string): Promise<void> {
    await api.delete(`/packages/${packageId}/blacklist`)
  }

  // Scanning operations
  async createScan(request: ScanRequest): Promise<ScanResult> {
    const response = await api.post<ScanResult>('/scans', request)
    return response.data
  }

  async getScans(params: ScanListParams = {}): Promise<ScanListResponse> {
    const response = await api.get<ScanListResponse>('/scans', { params })
    return response.data
  }

  async getScan(id: string): Promise<ScanResult> {
    const response = await api.get<ScanResult>(`/scans/${id}`)
    return response.data
  }

  async cancelScan(id: string): Promise<void> {
    await api.post(`/scans/${id}/cancel`)
  }

  async deleteScan(id: string): Promise<void> {
    await api.delete(`/scans/${id}`)
  }

  async exportScanResults(id: string, format: 'json' | 'csv' | 'pdf'): Promise<void> {
    await api.downloadFile(`/scans/${id}/export?format=${format}`, `scan-${id}.${format}`)
  }

  // Project scanning
  async getProjects(): Promise<ProjectScan[]> {
    const response = await api.get<ProjectScan[]>('/projects')
    return response.data
  }

  async getProject(id: string): Promise<ProjectScan> {
    const response = await api.get<ProjectScan>(`/projects/${id}`)
    return response.data
  }

  async createProject(data: {
    name: string
    path: string
    type: string
    autoScan: boolean
  }): Promise<ProjectScan> {
    const response = await api.post<ProjectScan>('/projects', data)
    return response.data
  }

  async updateProject(
    id: string,
    data: Partial<{
      name: string
      path: string
      autoScan: boolean
    }>
  ): Promise<ProjectScan> {
    const response = await api.patch<ProjectScan>(`/projects/${id}`, data)
    return response.data
  }

  async deleteProject(id: string): Promise<void> {
    await api.delete(`/projects/${id}`)
  }

  async scanProject(id: string): Promise<ScanResult> {
    const response = await api.post<ScanResult>(`/projects/${id}/scan`)
    return response.data
  }

  // Bulk operations
  async bulkScan(packageNames: string[], registry: string): Promise<ScanResult> {
    const response = await api.post<ScanResult>('/scans/bulk', {
      packages: packageNames,
      registry,
    })
    return response.data
  }

  async bulkWhitelist(packageIds: string[]): Promise<void> {
    await api.post('/packages/bulk/whitelist', { packageIds })
  }

  async bulkBlacklist(packageIds: string[]): Promise<void> {
    await api.post('/packages/bulk/blacklist', { packageIds })
  }

  // Statistics
  async getPackageStats(): Promise<{
    total: number
    byRegistry: Record<string, number>
    byRiskLevel: Record<string, number>
    recentScans: number
  }> {
    const response = await api.get('/packages/stats')
    return response.data
  }

  async getThreatStats(): Promise<{
    total: number
    byType: Record<string, number>
    bySeverity: Record<string, number>
    trends: Array<{ date: string; count: number }>
  }> {
    const response = await api.get('/threats/stats')
    return response.data
  }
}

export const packageService = new PackageService()
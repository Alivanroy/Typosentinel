import { useState, useEffect, useCallback } from 'react'
import { apiService } from '../services/api'

// Generic hook for API calls with loading and error states
export function useApi<T>(
  apiCall: () => Promise<T>,
  dependencies: any[] = []
) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const result = await apiCall()
      setData(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }, dependencies)

  useEffect(() => {
    fetchData()
  }, [fetchData])

  return { data, loading, error, refetch: fetchData }
}

// Hook for dashboard data
export function useDashboard() {
  const stats = useApi(() => apiService.getDashboardStats())
  const systemStatus = useApi(() => apiService.getSystemStatus())
  const recentScans = useApi(() => apiService.getRecentScans())

  return {
    stats: stats.data,
    systemStatus: systemStatus.data,
    recentScans: recentScans.data,
    loading: stats.loading || systemStatus.loading || recentScans.loading,
    error: stats.error || systemStatus.error || recentScans.error,
    refetch: () => {
      stats.refetch()
      systemStatus.refetch()
      recentScans.refetch()
    }
  }
}

// Hook for security scans
export function useScans() {
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchScans = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const result = await apiService.getAllScans()
      setScans(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scans')
    } finally {
      setLoading(false)
    }
  }, [])

  const runScan = useCallback(async (scanId: string) => {
    try {
      const result = await apiService.runScan(scanId)
      if (result.success) {
        // Update the scan status locally
        setScans(prev => prev.map(scan => 
          scan.id === scanId 
            ? { ...scan, status: 'running', progress: 0 }
            : scan
        ))
        return result
      }
      throw new Error(result.message)
    } catch (err) {
      throw err
    }
  }, [])

  const pauseScan = useCallback(async (scanId: string) => {
    try {
      const result = await apiService.pauseScan(scanId)
      if (result.success) {
        setScans(prev => prev.map(scan => 
          scan.id === scanId 
            ? { ...scan, status: 'paused' }
            : scan
        ))
        return result
      }
      throw new Error(result.message)
    } catch (err) {
      throw err
    }
  }, [])

  const createScan = useCallback(async (scanConfig: {
    name: string
    target: string
    type: string
  }) => {
    try {
      const result = await apiService.createNewScan(scanConfig)
      if (result.success) {
        await fetchScans() // Refresh the list
        return result
      }
      throw new Error(result.message)
    } catch (err) {
      throw err
    }
  }, [fetchScans])

  useEffect(() => {
    fetchScans()
  }, [fetchScans])

  return {
    scans,
    loading,
    error,
    refetch: fetchScans,
    runScan,
    pauseScan,
    createScan
  }
}

// Hook for reports
export function useReports() {
  const [reports, setReports] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchReports = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const result = await apiService.getAllReports()
      setReports(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch reports')
    } finally {
      setLoading(false)
    }
  }, [])

  const generateReport = useCallback(async (reportConfig: {
    type: string
    title: string
    description?: string
    format?: string
  }) => {
    try {
      const result = await apiService.generateReport(reportConfig)
      if (result.success) {
        // Add the new report to the list with generating status
        const newReport = {
          id: result.reportId,
          title: reportConfig.title,
          type: reportConfig.type,
          description: reportConfig.description || '',
          generatedDate: new Date().toISOString().split('T')[0],
          status: 'generating',
          format: reportConfig.format || 'PDF',
          size: 'Generating...',
          author: 'Current User',
          tags: [reportConfig.type],
        }
        setReports(prev => [newReport, ...prev])
        return result
      }
      throw new Error(result.message)
    } catch (err) {
      throw err
    }
  }, [])

  const downloadReport = useCallback(async (reportId: string, filename: string) => {
    try {
      const blob = await apiService.downloadReport(reportId)
      
      // Create download link
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
      
      return { success: true, message: 'Report downloaded successfully' }
    } catch (err) {
      throw err
    }
  }, [])

  const scheduleReport = useCallback(async (scheduleConfig: {
    reportType: string
    frequency: string
    recipients: string[]
  }) => {
    try {
      const result = await apiService.scheduleReport(scheduleConfig)
      return result
    } catch (err) {
      throw err
    }
  }, [])

  useEffect(() => {
    fetchReports()
  }, [fetchReports])

  return {
    reports,
    loading,
    error,
    refetch: fetchReports,
    generateReport,
    downloadReport,
    scheduleReport
  }
}
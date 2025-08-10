import { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  FileText, 
  Download, 
  Calendar, 
  Search,
  Eye,
  Share2,
  Clock,
  CheckCircle,
  AlertTriangle,
  BarChart3,
  TrendingUp,
  FileBarChart,
  Shield,
  Bug,
  Package,
  X,
  Send,
  Settings,
  Users
} from 'lucide-react'
import { Card, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { useReports } from '../hooks/useApi'
import { useNotifications } from '../contexts/NotificationContext'

const reports = [
  {
    id: 'RPT-001',
    title: 'Weekly Security Summary',
    type: 'security',
    description: 'Comprehensive security analysis for the past week including vulnerability scans and threat assessments.',
    generatedDate: '2023-10-20',
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
    generatedDate: '2023-10-18',
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
    generatedDate: '2023-10-15',
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
    generatedDate: '2023-10-10',
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
    title: 'Executive Summary',
    type: 'executive',
    description: 'High-level security overview for executive leadership and stakeholders.',
    generatedDate: '2023-10-05',
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
  }
]

const reportTemplates = [
  {
    id: 'template-1',
    name: 'Security Summary',
    description: 'Weekly or monthly security overview',
    icon: Shield,
    color: 'text-blue-600 bg-blue-100'
  },
  {
    id: 'template-2',
    name: 'Vulnerability Report',
    description: 'Detailed vulnerability analysis',
    icon: Bug,
    color: 'text-red-600 bg-red-100'
  },
  {
    id: 'template-3',
    name: 'Dependency Audit',
    description: 'Package and dependency analysis',
    icon: Package,
    color: 'text-green-600 bg-green-100'
  },
  {
    id: 'template-4',
    name: 'Compliance Report',
    description: 'Regulatory compliance assessment',
    icon: FileBarChart,
    color: 'text-purple-600 bg-purple-100'
  }
]

export function Reports() {
  const [filter, setFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [activeTab, setActiveTab] = useState('reports')
  const [showScheduleModal, setShowScheduleModal] = useState(false)
  const [showGenerateModal, setShowGenerateModal] = useState(false)
  const [showViewModal, setShowViewModal] = useState(false)
  const [selectedReport, setSelectedReport] = useState<any>(null)
  const [selectedReports, setSelectedReports] = useState<string[]>([])
  const [showBulkActions, setShowBulkActions] = useState(false)

  const {
    reports: apiReports,
    generateReport,
    downloadReport,
    scheduleReport 
  } = useReports()
  const { success, showError, info } = useNotifications()

  // Use API reports if available, otherwise fall back to mock data
  const reportsData = apiReports || reports

  const filteredReports = reportsData.filter(report => {
    const matchesSearch = report.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         report.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         (report.tags && report.tags.some((tag: string) => tag.toLowerCase().includes(searchTerm.toLowerCase())))
    const matchesType = filter === 'all' || report.type === filter
    const matchesStatus = statusFilter === 'all' || report.status === statusFilter
    return matchesSearch && matchesType && matchesStatus
  })

  const handleGenerateReport = async (templateId: string) => {
    try {
      await generateReport({
        title: `Generated Report - ${new Date().toLocaleDateString()}`,
        type: 'security',
        description: `Generated from template ${templateId}`,
        format: 'PDF'
      })
      success('Report generation started successfully!')
    } catch (error) {
      showError('Failed to generate report')
    }
  }

  const handleDownloadReport = async (reportId: string, title: string) => {
    try {
      const result = await downloadReport(reportId, 'PDF')
      if (result.success) {
        // Create a mock PDF download
        const content = `Report: ${title}\nGenerated: ${new Date().toISOString()}\n\nThis is a mock PDF content.`
        const blob = new Blob([content], { type: 'application/pdf' })
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `${title.replace(/\s+/g, '_')}.pdf`
        a.click()
        window.URL.revokeObjectURL(url)
        success('Report downloaded successfully!')
      }
    } catch (error) {
      showError('Failed to download report')
    }
  }

  const handleScheduleReport = async (scheduleData?: any) => {
    if (!scheduleData) {
      setShowScheduleModal(true)
      return
    }
    
    try {
      await scheduleReport(scheduleData)
      success('Report scheduled successfully!')
      setShowScheduleModal(false)
    } catch (error) {
      showError('Failed to schedule report')
    }
  }

  const handleViewReport = (reportId: string) => {
    const report = reportsData.find(r => r.id === reportId)
    if (report) {
      setSelectedReport(report)
      setShowViewModal(true)
    }
  }

  const handleBulkDownload = async () => {
    if (selectedReports.length === 0) return
    
    try {
      for (const reportId of selectedReports) {
        const report = reportsData.find(r => r.id === reportId)
        if (report && report.status === 'completed') {
          await handleDownloadReport(reportId, report.title)
        }
      }
      setSelectedReports([])
      setShowBulkActions(false)
      success(`Downloaded ${selectedReports.length} reports successfully!`)
    } catch (error) {
      showError('Failed to download reports')
    }
  }

  const handleBulkDelete = async () => {
    if (selectedReports.length === 0) return
    
    try {
      // In a real app, this would call an API to delete reports
      info(`Deleted ${selectedReports.length} reports`)
      setSelectedReports([])
      setShowBulkActions(false)
    } catch (error) {
      showError('Failed to delete reports')
    }
  }

  const toggleReportSelection = (reportId: string) => {
    setSelectedReports(prev => 
      prev.includes(reportId) 
        ? prev.filter(id => id !== reportId)
        : [...prev, reportId]
    )
  }

  const selectAllReports = () => {
    if (selectedReports.length === filteredReports.length) {
      setSelectedReports([])
    } else {
      setSelectedReports(filteredReports.map(r => r.id))
    }
  }

  const handleShareReport = (reportId: string, title: string) => {
    if (navigator.share) {
      navigator.share({
        title: title,
        text: `Check out this security report: ${title}`,
        url: `${window.location.origin}/reports/${reportId}`
      })
    } else {
      // Fallback: copy to clipboard
      navigator.clipboard.writeText(`${window.location.origin}/reports/${reportId}`)
      info('Report link copied to clipboard!')
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />
      case 'generating':
        return <Clock className="w-4 h-4 text-yellow-500" />
      case 'failed':
        return <AlertTriangle className="w-4 h-4 text-red-500" />
      default:
        return <Clock className="w-4 h-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'text-green-700 bg-green-100 border-green-200'
      case 'generating':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      case 'failed':
        return 'text-red-700 bg-red-100 border-red-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'security':
        return <Shield className="w-5 h-5 text-blue-500" />
      case 'dependencies':
        return <Package className="w-5 h-5 text-green-500" />
      case 'compliance':
        return <FileBarChart className="w-5 h-5 text-purple-500" />
      case 'analytics':
        return <TrendingUp className="w-5 h-5 text-orange-500" />
      case 'executive':
        return <BarChart3 className="w-5 h-5 text-indigo-500" />
      default:
        return <FileText className="w-5 h-5 text-gray-500" />
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
          <h1 className="text-3xl font-bold tracking-tight">Reports</h1>
          <p className="text-gray-600">
            Generate and manage security reports and analytics
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-2">
          {selectedReports.length > 0 && (
            <div className="flex space-x-2 mr-4">
              <Button variant="outline" size="sm" onClick={handleBulkDownload}>
                <Download className="w-4 h-4 mr-2" />
                Download ({selectedReports.length})
              </Button>
              <Button variant="outline" size="sm" onClick={handleBulkDelete}>
                <AlertTriangle className="w-4 h-4 mr-2" />
                Delete ({selectedReports.length})
              </Button>
            </div>
          )}
          <Button variant="outline" onClick={() => handleScheduleReport()}>
            <Calendar className="w-4 h-4 mr-2" />
            Schedule Report
          </Button>
          <Button onClick={() => setShowGenerateModal(true)}>
            <FileText className="w-4 h-4 mr-2" />
            Generate Report
          </Button>
        </div>
      </motion.div>

      {/* Tabs */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="border-b border-gray-200"
      >
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('reports')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'reports'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <FileText className="w-4 h-4 inline mr-2" />
            Generated Reports
          </button>
          <button
            onClick={() => setActiveTab('templates')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'templates'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            <FileBarChart className="w-4 h-4 inline mr-2" />
            Report Templates
          </button>
        </nav>
      </motion.div>

      {activeTab === 'reports' && (
        <>
          {/* Stats Cards */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="grid grid-cols-1 md:grid-cols-4 gap-4"
          >
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Total Reports</p>
                    <p className="text-2xl font-bold">{reportsData.length}</p>
                  </div>
                  <FileText className="w-8 h-8 text-blue-500" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">This Week</p>
                    <p className="text-2xl font-bold">{reportsData.filter(r => {
                      const reportDate = new Date(r.generatedDate);
                      const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
                      return reportDate >= weekAgo;
                    }).length}</p>
                  </div>
                  <Calendar className="w-8 h-8 text-green-500" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Generating</p>
                    <p className="text-2xl font-bold">{reportsData.filter(r => r.status === 'generating').length}</p>
                  </div>
                  <Clock className="w-8 h-8 text-yellow-500" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Completed</p>
                    <p className="text-2xl font-bold">{reportsData.filter(r => r.status === 'completed').length}</p>
                  </div>
                  <CheckCircle className="w-8 h-8 text-purple-500" />
                </div>
              </CardContent>
            </Card>
          </motion.div>

          {/* Filters */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="flex flex-col sm:flex-row gap-4"
          >
            <div className="flex items-center space-x-4">
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={selectedReports.length === filteredReports.length && filteredReports.length > 0}
                  onChange={selectAllReports}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm text-gray-600">
                  Select All ({filteredReports.length})
                </span>
              </label>
            </div>
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                placeholder="Search reports..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 w-full bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div className="flex space-x-2">
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="px-3 py-2 bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Types</option>
                <option value="security">Security</option>
                <option value="dependencies">Dependencies</option>
                <option value="compliance">Compliance</option>
                <option value="analytics">Analytics</option>
                <option value="executive">Executive</option>
              </select>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-3 py-2 bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Statuses</option>
                <option value="completed">Completed</option>
                <option value="generating">Generating</option>
                <option value="failed">Failed</option>
              </select>
            </div>
          </motion.div>

          {/* Reports List */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="space-y-4"
          >
            {filteredReports.map((report, index) => (
              <motion.div
                key={report.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 * index }}
              >
                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-6">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-4 flex-1">
                        <input
                          type="checkbox"
                          checked={selectedReports.includes(report.id)}
                          onChange={() => toggleReportSelection(report.id)}
                          className="mt-1 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                        />
                        <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          {getTypeIcon(report.type)}
                          <h3 className="text-lg font-semibold">{report.title}</h3>
                          <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(report.status)}`}>
                            {getStatusIcon(report.status)}
                            <span className="ml-1">{report.status.toUpperCase()}</span>
                          </span>
                        </div>
                        <p className="text-gray-700 mb-3">{report.description}</p>
                        <div className="flex items-center space-x-4 text-sm text-gray-600 mb-3">
                          <div className="flex items-center">
                            <Calendar className="w-4 h-4 mr-1" />
                            {report.generatedDate}
                          </div>
                          <div className="flex items-center">
                            <FileText className="w-4 h-4 mr-1" />
                            {report.format}
                          </div>
                          <div className="flex items-center">
                            <Download className="w-4 h-4 mr-1" />
                            {report.size}
                          </div>
                          <div>
                            by {report.author}
                          </div>
                        </div>
                        <div className="flex items-center space-x-4 text-sm">
                          <div className="flex items-center text-red-600">
                            <Bug className="w-4 h-4 mr-1" />
                            {report.metrics?.vulnerabilities || 0} vulnerabilities
                          </div>
                          <div className="flex items-center text-blue-600">
                            <Shield className="w-4 h-4 mr-1" />
                            {report.metrics?.scans || 0} scans
                          </div>
                          <div className="flex items-center text-green-600">
                            <Package className="w-4 h-4 mr-1" />
                            {report.metrics?.packages || 0} packages
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-1 mt-3">
                          {report.tags?.map((tag: string) => (
                            <span
                              key={tag}
                              className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded-md"
                            >
                              {tag}
                            </span>
                          )) || null}
                        </div>
                        </div>
                      </div>
                      <div className="flex space-x-2 ml-4">
                        <Button variant="outline" size="sm" onClick={() => handleViewReport(report.id)}>
                          <Eye className="w-4 h-4 mr-1" />
                          View
                        </Button>
                        {report.status === 'completed' && (
                          <>
                            <Button variant="outline" size="sm" onClick={() => handleDownloadReport(report.id, report.title)}>
                              <Download className="w-4 h-4 mr-1" />
                              Download
                            </Button>
                            <Button variant="outline" size="sm" onClick={() => handleShareReport(report.id, report.title)}>
                              <Share2 className="w-4 h-4 mr-1" />
                              Share
                            </Button>
                          </>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </motion.div>
        </>
      )}

      {activeTab === 'templates' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
        >
          {reportTemplates.map((template, index) => (
            <motion.div
              key={template.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 * index }}
            >
              <Card className="hover:shadow-md transition-shadow cursor-pointer">
                <CardContent className="p-6 text-center">
                  <div className={`w-16 h-16 rounded-full ${template.color} flex items-center justify-center mx-auto mb-4`}>
                    <template.icon className="w-8 h-8" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2">{template.name}</h3>
                  <p className="text-gray-600 text-sm mb-4">{template.description}</p>
                  <Button className="w-full" onClick={() => handleGenerateReport(template.id)}>
                    <FileText className="w-4 h-4 mr-2" />
                    Generate Report
                  </Button>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </motion.div>
      )}

      {filteredReports.length === 0 && activeTab === 'reports' && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-12"
        >
          <FileText className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No reports found</h3>
          <p className="text-gray-600">
            {searchTerm || filter !== 'all' || statusFilter !== 'all'
              ? 'Try adjusting your filters to see more results.'
              : 'Generate your first security report to get started.'}
          </p>
        </motion.div>
      )}

      {/* Schedule Report Modal */}
      {showScheduleModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Schedule Report</h3>
              <button onClick={() => setShowScheduleModal(false)}>
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Report Type</label>
                <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                  <option value="security">Security Report</option>
                  <option value="dependencies">Dependency Audit</option>
                  <option value="compliance">Compliance Report</option>
                  <option value="analytics">Analytics Report</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Frequency</label>
                <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                  <option value="quarterly">Quarterly</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Recipients</label>
                <input
                  type="email"
                  placeholder="admin@example.com"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div className="flex space-x-2 pt-4">
                <Button variant="outline" onClick={() => setShowScheduleModal(false)} className="flex-1">
                  Cancel
                </Button>
                <Button onClick={() => handleScheduleReport({
                  reportType: 'security',
                  frequency: 'weekly',
                  recipients: ['admin@example.com']
                })} className="flex-1">
                  <Send className="w-4 h-4 mr-2" />
                  Schedule
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-2xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Generate New Report</h3>
              <button onClick={() => setShowGenerateModal(false)}>
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {reportTemplates.map((template) => (
                <Card key={template.id} className="hover:shadow-md transition-shadow cursor-pointer" onClick={() => {
                  handleGenerateReport(template.id)
                  setShowGenerateModal(false)
                }}>
                  <CardContent className="p-4 text-center">
                    <div className={`w-12 h-12 rounded-full ${template.color} flex items-center justify-center mx-auto mb-3`}>
                      <template.icon className="w-6 h-6" />
                    </div>
                    <h4 className="font-semibold mb-1">{template.name}</h4>
                    <p className="text-gray-600 text-sm">{template.description}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
            <div className="flex justify-end pt-4">
              <Button variant="outline" onClick={() => setShowGenerateModal(false)}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* View Report Modal */}
      {showViewModal && selectedReport && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Report Viewer</h3>
              <button onClick={() => setShowViewModal(false)}>
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-6">
              <div className="border-b pb-4">
                <div className="flex items-center space-x-3 mb-2">
                  {getTypeIcon(selectedReport.type)}
                  <h2 className="text-xl font-bold">{selectedReport.title}</h2>
                  <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(selectedReport.status)}`}>
                    {selectedReport.status.toUpperCase()}
                  </span>
                </div>
                <p className="text-gray-700">{selectedReport.description}</p>
                <div className="flex items-center space-x-4 text-sm text-gray-600 mt-2">
                  <span>Generated: {selectedReport.generatedDate}</span>
                  <span>By: {selectedReport.author}</span>
                  <span>Format: {selectedReport.format}</span>
                  <span>Size: {selectedReport.size}</span>
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card>
                  <CardContent className="p-4 text-center">
                    <Bug className="w-8 h-8 text-red-500 mx-auto mb-2" />
                    <div className="text-2xl font-bold text-red-600">{selectedReport.metrics?.vulnerabilities || 0}</div>
                    <div className="text-sm text-gray-600">Vulnerabilities</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4 text-center">
                    <Shield className="w-8 h-8 text-blue-500 mx-auto mb-2" />
                    <div className="text-2xl font-bold text-blue-600">{selectedReport.metrics?.scans || 0}</div>
                    <div className="text-sm text-gray-600">Security Scans</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4 text-center">
                    <Package className="w-8 h-8 text-green-500 mx-auto mb-2" />
                    <div className="text-2xl font-bold text-green-600">{selectedReport.metrics?.packages || 0}</div>
                    <div className="text-sm text-gray-600">Packages Analyzed</div>
                  </CardContent>
                </Card>
              </div>

              <div className="bg-gray-50 p-4 rounded-lg">
                <h4 className="font-semibold mb-2">Report Preview</h4>
                <div className="bg-white p-4 rounded border min-h-[200px]">
                  <p className="text-gray-600 text-center py-8">
                    📄 Report content would be displayed here in a real application.
                    <br />
                    This could include charts, tables, and detailed analysis.
                  </p>
                </div>
              </div>

              <div className="flex space-x-2 pt-4">
                <Button variant="outline" onClick={() => setShowViewModal(false)} className="flex-1">
                  Close
                </Button>
                {selectedReport.status === 'completed' && (
                  <>
                    <Button onClick={() => handleDownloadReport(selectedReport.id, selectedReport.title)} className="flex-1">
                      <Download className="w-4 h-4 mr-2" />
                      Download
                    </Button>
                    <Button variant="outline" onClick={() => handleShareReport(selectedReport.id, selectedReport.title)}>
                      <Share2 className="w-4 h-4 mr-2" />
                      Share
                    </Button>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
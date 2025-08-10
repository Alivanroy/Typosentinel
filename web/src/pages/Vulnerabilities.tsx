import { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  AlertTriangle, 
  Shield, 
  Clock, 
  Search,
  Download,
  Eye,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Package,
  Calendar,
  Zap,
  AlertCircle,
  CheckCircle2,
  X,
  Copy,
  FileText,
  Bug,
  Link
} from 'lucide-react'
import { Card, CardContent } from '../components/ui/Card'
import { Button } from '../components/ui/Button'

const vulnerabilities = [
  {
    id: 'CVE-2023-1234',
    title: 'Cross-Site Scripting (XSS) in lodash',
    package: 'lodash',
    version: '4.17.20',
    severity: 'high',
    score: 8.2,
    description: 'A cross-site scripting vulnerability exists in lodash that allows attackers to execute arbitrary JavaScript code.',
    publishedDate: '2023-10-15',
    lastModified: '2023-10-20',
    status: 'open',
    affectedVersions: '< 4.17.21',
    fixedVersion: '4.17.21',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-1234',
      'https://github.com/lodash/lodash/security/advisories'
    ]
  },
  {
    id: 'CVE-2023-5678',
    title: 'Remote Code Execution in express',
    package: 'express',
    version: '4.17.1',
    severity: 'critical',
    score: 9.8,
    description: 'A remote code execution vulnerability in Express.js allows attackers to execute arbitrary code on the server.',
    publishedDate: '2023-09-28',
    lastModified: '2023-10-01',
    status: 'fixed',
    affectedVersions: '< 4.18.2',
    fixedVersion: '4.18.2',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-5678',
      'https://expressjs.com/en/advanced/security-updates.html'
    ]
  },
  {
    id: 'CVE-2023-9012',
    title: 'SQL Injection in mysql2',
    package: 'mysql2',
    version: '2.3.0',
    severity: 'medium',
    score: 6.5,
    description: 'SQL injection vulnerability in mysql2 driver allows attackers to manipulate database queries.',
    publishedDate: '2023-08-12',
    lastModified: '2023-08-15',
    status: 'investigating',
    affectedVersions: '< 2.3.3',
    fixedVersion: '2.3.3',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-9012'
    ]
  },
  {
    id: 'CVE-2023-3456',
    title: 'Prototype Pollution in minimist',
    package: 'minimist',
    version: '1.2.5',
    severity: 'low',
    score: 3.7,
    description: 'Prototype pollution vulnerability in minimist allows modification of object prototypes.',
    publishedDate: '2023-07-05',
    lastModified: '2023-07-10',
    status: 'open',
    affectedVersions: '< 1.2.6',
    fixedVersion: '1.2.6',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-3456'
    ]
  }
]

export function Vulnerabilities() {
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null)
  const [showDetailsModal, setShowDetailsModal] = useState(false)
  const [selectedVuln, setSelectedVuln] = useState<any>(null)

  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    const matchesSearch = vuln.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         vuln.package.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         vuln.id.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesSeverity = severityFilter === 'all' || vuln.severity === severityFilter
    const matchesStatus = statusFilter === 'all' || vuln.status === statusFilter
    return matchesSearch && matchesSeverity && matchesStatus
  })

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-700 bg-red-100 border-red-200'
      case 'high':
        return 'text-orange-700 bg-orange-100 border-orange-200'
      case 'medium':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      case 'low':
        return 'text-blue-700 bg-blue-100 border-blue-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'fixed':
        return <CheckCircle2 className="w-4 h-4 text-green-500" />
      case 'investigating':
        return <Clock className="w-4 h-4 text-yellow-500" />
      case 'open':
        return <AlertCircle className="w-4 h-4 text-red-500" />
      default:
        return <AlertTriangle className="w-4 h-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'fixed':
        return 'text-green-700 bg-green-100 border-green-200'
      case 'investigating':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      case 'open':
        return 'text-red-700 bg-red-100 border-red-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const handleViewDetails = (vuln: any) => {
    setSelectedVuln(vuln)
    setShowDetailsModal(true)
  }

  const handleCloseDetails = () => {
    setShowDetailsModal(false)
    setSelectedVuln(null)
  }

  const handleCopyId = (id: string) => {
    navigator.clipboard.writeText(id)
  }

  const severityCounts = {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length
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
          <h1 className="text-3xl font-bold tracking-tight">Vulnerabilities</h1>
          <p className="text-gray-600">
            Track and manage security vulnerabilities in your dependencies
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-2">
          <Button variant="outline">
            <Download className="w-4 h-4 mr-2" />
            Export Report
          </Button>
          <Button>
            <Shield className="w-4 h-4 mr-2" />
            Scan Now
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
                <p className="text-sm font-medium text-gray-600">Critical</p>
                <p className="text-2xl font-bold text-red-600">{severityCounts.critical}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">High</p>
                <p className="text-2xl font-bold text-orange-600">{severityCounts.high}</p>
              </div>
              <Zap className="w-8 h-8 text-orange-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Medium</p>
                <p className="text-2xl font-bold text-yellow-600">{severityCounts.medium}</p>
              </div>
              <AlertCircle className="w-8 h-8 text-yellow-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Low</p>
                <p className="text-2xl font-bold text-blue-600">{severityCounts.low}</p>
              </div>
              <Shield className="w-8 h-8 text-blue-500" />
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="flex flex-col sm:flex-row gap-4"
      >
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search vulnerabilities..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10 pr-4 py-2 w-full bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex space-x-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 bg-white border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="fixed">Fixed</option>
          </select>
        </div>
      </motion.div>

      {/* Vulnerabilities List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="space-y-4"
      >
        {filteredVulnerabilities.map((vuln, index) => (
          <motion.div
            key={vuln.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 * index }}
          >
            <Card className="hover:shadow-md transition-shadow">
              <CardContent className="p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h3 className="text-lg font-semibold">{vuln.title}</h3>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(vuln.status)}`}>
                        {getStatusIcon(vuln.status)}
                        <span className="ml-1">{vuln.status.toUpperCase()}</span>
                      </span>
                    </div>
                    <div className="flex items-center space-x-4 text-sm text-gray-600 mb-3">
                      <div className="flex items-center">
                        <Package className="w-4 h-4 mr-1" />
                        {vuln.package} v{vuln.version}
                      </div>
                      <div className="flex items-center">
                        <AlertTriangle className="w-4 h-4 mr-1" />
                        CVSS {vuln.score}
                      </div>
                      <div className="flex items-center">
                        <Calendar className="w-4 h-4 mr-1" />
                        {vuln.publishedDate}
                      </div>
                    </div>
                    <p className="text-gray-700 mb-3">{vuln.description}</p>
                    
                    {expandedVuln === vuln.id && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="border-t pt-4 mt-4 space-y-3"
                      >
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <h4 className="font-medium text-gray-900 mb-1">Affected Versions</h4>
                            <p className="text-sm text-gray-600">{vuln.affectedVersions}</p>
                          </div>
                          <div>
                            <h4 className="font-medium text-gray-900 mb-1">Fixed Version</h4>
                            <p className="text-sm text-gray-600">{vuln.fixedVersion}</p>
                          </div>
                        </div>
                        <div>
                          <h4 className="font-medium text-gray-900 mb-2">References</h4>
                          <div className="space-y-1">
                            {vuln.references.map((ref, idx) => (
                              <a
                                key={idx}
                                href={ref}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="flex items-center text-sm text-blue-600 hover:text-blue-800"
                              >
                                <ExternalLink className="w-3 h-3 mr-1" />
                                {ref}
                              </a>
                            ))}
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </div>
                  <div className="flex space-x-2 ml-4">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
                    >
                      {expandedVuln === vuln.id ? (
                        <>
                          <ChevronUp className="w-4 h-4 mr-1" />
                          Less
                        </>
                      ) : (
                        <>
                          <ChevronDown className="w-4 h-4 mr-1" />
                          More
                        </>
                      )}
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => handleViewDetails(vuln)}>
                      <Eye className="w-4 h-4 mr-1" />
                      Details
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </motion.div>

      {filteredVulnerabilities.length === 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center py-12"
        >
          <Shield className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No vulnerabilities found</h3>
          <p className="text-gray-600">
            {searchTerm || severityFilter !== 'all' || statusFilter !== 'all'
              ? 'Try adjusting your filters to see more results.'
              : 'Great! No vulnerabilities detected in your dependencies.'}
          </p>
        </motion.div>
      )}

      {/* Vulnerability Details Modal */}
      {showDetailsModal && selectedVuln && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto"
          >
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b">
              <div className="flex items-center space-x-3">
                <Bug className="w-6 h-6 text-red-500" />
                <div>
                  <h2 className="text-xl font-semibold">{selectedVuln.title}</h2>
                  <div className="flex items-center space-x-2 mt-1">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(selectedVuln.severity)}`}>
                      {selectedVuln.severity.toUpperCase()}
                    </span>
                    <span className="text-sm text-gray-500">CVSS {selectedVuln.score}</span>
                  </div>
                </div>
              </div>
              <Button variant="ghost" size="sm" onClick={handleCloseDetails}>
                <X className="w-5 h-5" />
              </Button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6">
              {/* Basic Information */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 mb-2">Vulnerability ID</h3>
                    <div className="flex items-center space-x-2">
                      <code className="px-2 py-1 bg-gray-100 rounded text-sm font-mono">{selectedVuln.id}</code>
                      <Button variant="ghost" size="sm" onClick={() => handleCopyId(selectedVuln.id)}>
                        <Copy className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 mb-2">Affected Package</h3>
                    <div className="flex items-center space-x-2">
                      <Package className="w-4 h-4 text-gray-500" />
                      <span className="font-mono">{selectedVuln.package} v{selectedVuln.version}</span>
                    </div>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 mb-2">Status</h3>
                    <div className="flex items-center space-x-2">
                      {getStatusIcon(selectedVuln.status)}
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(selectedVuln.status)}`}>
                        {selectedVuln.status.toUpperCase()}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 mb-2">Published Date</h3>
                    <div className="flex items-center space-x-2">
                      <Calendar className="w-4 h-4 text-gray-500" />
                      <span>{selectedVuln.publishedDate}</span>
                    </div>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 mb-2">Last Modified</h3>
                    <div className="flex items-center space-x-2">
                      <Clock className="w-4 h-4 text-gray-500" />
                      <span>{selectedVuln.lastModified}</span>
                    </div>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-gray-900 mb-2">CVSS Score</h3>
                    <div className="flex items-center space-x-2">
                      <AlertTriangle className="w-4 h-4 text-orange-500" />
                      <span className="font-semibold">{selectedVuln.score}/10</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Description */}
              <div>
                <h3 className="text-sm font-medium text-gray-900 mb-2">Description</h3>
                <p className="text-gray-700 leading-relaxed">{selectedVuln.description}</p>
              </div>

              {/* Version Information */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="text-sm font-medium text-gray-900 mb-2">Affected Versions</h3>
                  <code className="px-3 py-2 bg-red-50 border border-red-200 rounded text-sm font-mono block">
                    {selectedVuln.affectedVersions}
                  </code>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-gray-900 mb-2">Fixed Version</h3>
                  <code className="px-3 py-2 bg-green-50 border border-green-200 rounded text-sm font-mono block">
                    {selectedVuln.fixedVersion}
                  </code>
                </div>
              </div>

              {/* References */}
              <div>
                <h3 className="text-sm font-medium text-gray-900 mb-3">References</h3>
                <div className="space-y-2">
                  {selectedVuln.references.map((ref: string, idx: number) => (
                    <a
                      key={idx}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center space-x-2 text-blue-600 hover:text-blue-800 p-2 rounded hover:bg-blue-50 transition-colors"
                    >
                      <Link className="w-4 h-4" />
                      <span className="text-sm">{ref}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  ))}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex space-x-3 pt-4 border-t">
                <Button className="flex-1">
                  <FileText className="w-4 h-4 mr-2" />
                  Generate Report
                </Button>
                <Button variant="outline" className="flex-1">
                  <Download className="w-4 h-4 mr-2" />
                  Export Details
                </Button>
                <Button variant="outline" onClick={handleCloseDetails}>
                  Close
                </Button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  )
}
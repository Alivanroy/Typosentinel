import React, { useState, useEffect, useMemo } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import './Reports.css';

const Reports = () => {
  const dispatch = useDispatch();
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedReport, setSelectedReport] = useState(null);
  const [filters, setFilters] = useState({
    type: 'all',
    status: 'all',
    dateRange: '30d'
  });
  const [sortBy, setSortBy] = useState('createdAt');
  const [sortOrder, setSortOrder] = useState('desc');
  const [searchTerm, setSearchTerm] = useState('');
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [generateForm, setGenerateForm] = useState({
    type: 'security-summary',
    title: '',
    description: '',
    includeCharts: true,
    includeDetails: true,
    dateRange: '30d'
  });

  // Mock data for development
  const mockReports = [
    {
      id: 'RPT-001',
      title: 'Monthly Security Summary',
      description: 'Comprehensive security analysis for January 2024',
      type: 'security-summary',
      status: 'completed',
      createdAt: '2024-01-31T10:30:00Z',
      completedAt: '2024-01-31T10:35:00Z',
      createdBy: 'System',
      fileSize: '2.4 MB',
      format: 'PDF',
      downloadUrl: '/api/reports/RPT-001/download',
      metrics: {
        totalScans: 45,
        threatsFound: 12,
        vulnerabilities: 8,
        packagesScanned: 1250
      },
      dateRange: {
        start: '2024-01-01T00:00:00Z',
        end: '2024-01-31T23:59:59Z'
      }
    },
    {
      id: 'RPT-002',
      title: 'Critical Vulnerabilities Report',
      description: 'Detailed analysis of critical security vulnerabilities',
      type: 'vulnerability-analysis',
      status: 'completed',
      createdAt: '2024-01-28T14:20:00Z',
      completedAt: '2024-01-28T14:25:00Z',
      createdBy: 'admin@typosentinel.com',
      fileSize: '1.8 MB',
      format: 'PDF',
      downloadUrl: '/api/reports/RPT-002/download',
      metrics: {
        criticalThreats: 3,
        highThreats: 5,
        affectedPackages: 8,
        recommendedActions: 12
      },
      dateRange: {
        start: '2024-01-15T00:00:00Z',
        end: '2024-01-28T23:59:59Z'
      }
    },
    {
      id: 'RPT-003',
      title: 'Compliance Audit Report',
      description: 'Security compliance assessment and recommendations',
      type: 'compliance',
      status: 'generating',
      createdAt: '2024-01-30T16:45:00Z',
      completedAt: null,
      createdBy: 'security@typosentinel.com',
      fileSize: null,
      format: 'PDF',
      downloadUrl: null,
      metrics: null,
      dateRange: {
        start: '2024-01-01T00:00:00Z',
        end: '2024-01-30T23:59:59Z'
      }
    },
    {
      id: 'RPT-004',
      title: 'Package Dependencies Analysis',
      description: 'Comprehensive analysis of package dependencies and risks',
      type: 'dependency-analysis',
      status: 'failed',
      createdAt: '2024-01-29T09:15:00Z',
      completedAt: '2024-01-29T09:20:00Z',
      createdBy: 'System',
      fileSize: null,
      format: 'PDF',
      downloadUrl: null,
      error: 'Insufficient data for analysis period',
      dateRange: {
        start: '2024-01-20T00:00:00Z',
        end: '2024-01-29T23:59:59Z'
      }
    }
  ];

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      setReports(mockReports);
    } catch (err) {
      setError('Failed to fetch reports');
      console.error('Error fetching reports:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredAndSortedReports = useMemo(() => {
    let filtered = reports.filter(report => {
      const matchesSearch = report.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           report.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           report.id.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesType = filters.type === 'all' || report.type === filters.type;
      const matchesStatus = filters.status === 'all' || report.status === filters.status;
      
      // Date range filter
      let matchesDateRange = true;
      if (filters.dateRange !== 'all') {
        const now = new Date();
        const reportDate = new Date(report.createdAt);
        const daysAgo = parseInt(filters.dateRange.replace('d', ''));
        const cutoffDate = new Date(now.getTime() - (daysAgo * 24 * 60 * 60 * 1000));
        matchesDateRange = reportDate >= cutoffDate;
      }
      
      return matchesSearch && matchesType && matchesStatus && matchesDateRange;
    });

    // Sort reports
    filtered.sort((a, b) => {
      let aValue, bValue;
      
      switch (sortBy) {
        case 'createdAt':
        case 'completedAt':
          aValue = new Date(a[sortBy] || 0);
          bValue = new Date(b[sortBy] || 0);
          break;
        case 'fileSize':
          aValue = parseFloat(a.fileSize?.replace(/[^0-9.]/g, '') || '0');
          bValue = parseFloat(b.fileSize?.replace(/[^0-9.]/g, '') || '0');
          break;
        default:
          aValue = a[sortBy]?.toLowerCase() || '';
          bValue = b[sortBy]?.toLowerCase() || '';
      }
      
      if (sortOrder === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });

    return filtered;
  }, [reports, filters, sortBy, sortOrder, searchTerm]);

  const reportStats = useMemo(() => {
    const stats = {
      total: reports.length,
      completed: 0,
      generating: 0,
      failed: 0,
      totalSize: 0
    };
    
    reports.forEach(report => {
      stats[report.status]++;
      if (report.fileSize) {
        const size = parseFloat(report.fileSize.replace(/[^0-9.]/g, ''));
        const unit = report.fileSize.includes('MB') ? 1 : 0.001;
        stats.totalSize += size * unit;
      }
    });
    
    return stats;
  }, [reports]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return '#059669';
      case 'generating': return '#d97706';
      case 'failed': return '#dc2626';
      case 'scheduled': return '#3b82f6';
      default: return '#6b7280';
    }
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'security-summary': return '🛡️';
      case 'vulnerability-analysis': return '🔍';
      case 'compliance': return '📋';
      case 'dependency-analysis': return '📦';
      case 'custom': return '📊';
      default: return '📄';
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const handleReportClick = (report) => {
    setSelectedReport(report);
  };

  const handleFilterChange = (filterType, value) => {
    setFilters(prev => ({
      ...prev,
      [filterType]: value
    }));
  };

  const handleGenerateReport = async () => {
    try {
      // Simulate report generation
      const newReport = {
        id: `RPT-${String(reports.length + 1).padStart(3, '0')}`,
        title: generateForm.title || `${generateForm.type.replace('-', ' ')} Report`,
        description: generateForm.description || 'Auto-generated report',
        type: generateForm.type,
        status: 'generating',
        createdAt: new Date().toISOString(),
        completedAt: null,
        createdBy: 'Current User',
        fileSize: null,
        format: 'PDF',
        downloadUrl: null,
        dateRange: {
          start: new Date(Date.now() - (parseInt(generateForm.dateRange.replace('d', '')) * 24 * 60 * 60 * 1000)).toISOString(),
          end: new Date().toISOString()
        }
      };
      
      setReports(prev => [newReport, ...prev]);
      setShowGenerateModal(false);
      setGenerateForm({
        type: 'security-summary',
        title: '',
        description: '',
        includeCharts: true,
        includeDetails: true,
        dateRange: '30d'
      });
      
      // Simulate completion after 3 seconds
      setTimeout(() => {
        setReports(prev => prev.map(report => 
          report.id === newReport.id 
            ? { 
                ...report, 
                status: 'completed', 
                completedAt: new Date().toISOString(),
                fileSize: '1.2 MB',
                downloadUrl: `/api/reports/${newReport.id}/download`
              }
            : report
        ));
      }, 3000);
    } catch (err) {
      console.error('Error generating report:', err);
    }
  };

  const clearFilters = () => {
    setFilters({
      type: 'all',
      status: 'all',
      dateRange: '30d'
    });
    setSearchTerm('');
  };

  if (loading) {
    return (
      <div className="reports">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading reports...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="reports">
        <div className="error-container">
          <div className="error-icon">⚠️</div>
          <h3>Error Loading Reports</h3>
          <p>{error}</p>
          <button className="retry-btn" onClick={fetchReports}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="reports">
      <div className="reports-header">
        <div className="header-content">
          <h1>Security Reports</h1>
          <div className="report-stats">
            <div className="stat">
              <div className="stat-value">{reportStats.total}</div>
              <div className="stat-label">Total Reports</div>
            </div>
            <div className="stat">
              <div className="stat-value" style={{ color: getStatusColor('completed') }}>
                {reportStats.completed}
              </div>
              <div className="stat-label">Completed</div>
            </div>
            <div className="stat">
              <div className="stat-value" style={{ color: getStatusColor('generating') }}>
                {reportStats.generating}
              </div>
              <div className="stat-label">Generating</div>
            </div>
            <div className="stat">
              <div className="stat-value">{reportStats.totalSize.toFixed(1)} MB</div>
              <div className="stat-label">Total Size</div>
            </div>
          </div>
        </div>
        <button 
          className="btn btn-primary generate-btn"
          onClick={() => setShowGenerateModal(true)}
        >
          Generate Report
        </button>
      </div>

      <div className="reports-controls">
        <div className="search-box">
          <input
            type="text"
            className="search-input"
            placeholder="Search reports by title, description, or ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        
        <div className="filter-controls">
          <select
            className="filter-select"
            value={filters.type}
            onChange={(e) => handleFilterChange('type', e.target.value)}
          >
            <option value="all">All Types</option>
            <option value="security-summary">Security Summary</option>
            <option value="vulnerability-analysis">Vulnerability Analysis</option>
            <option value="compliance">Compliance</option>
            <option value="dependency-analysis">Dependency Analysis</option>
            <option value="custom">Custom</option>
          </select>
          
          <select
            className="filter-select"
            value={filters.status}
            onChange={(e) => handleFilterChange('status', e.target.value)}
          >
            <option value="all">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="generating">Generating</option>
            <option value="failed">Failed</option>
            <option value="scheduled">Scheduled</option>
          </select>
          
          <select
            className="filter-select"
            value={filters.dateRange}
            onChange={(e) => handleFilterChange('dateRange', e.target.value)}
          >
            <option value="all">All Time</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
            <option value="90d">Last 90 Days</option>
          </select>
          
          <select
            className="sort-select"
            value={`${sortBy}-${sortOrder}`}
            onChange={(e) => {
              const [field, order] = e.target.value.split('-');
              setSortBy(field);
              setSortOrder(order);
            }}
          >
            <option value="createdAt-desc">Newest First</option>
            <option value="createdAt-asc">Oldest First</option>
            <option value="title-asc">Title (A to Z)</option>
            <option value="title-desc">Title (Z to A)</option>
            <option value="fileSize-desc">Largest First</option>
            <option value="fileSize-asc">Smallest First</option>
          </select>
          
          <button className="clear-filters-btn" onClick={clearFilters}>
            Clear Filters
          </button>
        </div>
      </div>

      {filteredAndSortedReports.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📄</div>
          <h3>No Reports Found</h3>
          <p>No reports match your current search and filter criteria.</p>
          <button 
            className="btn btn-primary"
            onClick={() => setShowGenerateModal(true)}
          >
            Generate Your First Report
          </button>
        </div>
      ) : (
        <div className="reports-list">
          {filteredAndSortedReports.map(report => (
            <div key={report.id} className="report-card" onClick={() => handleReportClick(report)}>
              <div className="report-card-header">
                <div className="report-info">
                  <div className="report-icon">{getTypeIcon(report.type)}</div>
                  <div className="report-details">
                    <h3>{report.title}</h3>
                    <p className="report-description">{report.description}</p>
                    <div className="report-meta">
                      <span className="report-id">{report.id}</span>
                      <span className="report-creator">by {report.createdBy}</span>
                      <span className="report-date">{formatDate(report.createdAt)}</span>
                    </div>
                  </div>
                </div>
                <div className="report-badges">
                  <span 
                    className="status-badge"
                    style={{ backgroundColor: getStatusColor(report.status) }}
                  >
                    {report.status}
                  </span>
                  {report.fileSize && (
                    <span className="size-badge">{report.fileSize}</span>
                  )}
                </div>
              </div>
              
              {report.metrics && (
                <div className="report-metrics">
                  {Object.entries(report.metrics).map(([key, value]) => (
                    <div key={key} className="metric">
                      <div className="metric-value">{value}</div>
                      <div className="metric-label">{key.replace(/([A-Z])/g, ' $1').toLowerCase()}</div>
                    </div>
                  ))}
                </div>
              )}
              
              <div className="report-card-actions">
                {report.status === 'completed' && report.downloadUrl && (
                  <button className="btn btn-primary btn-sm">
                    Download
                  </button>
                )}
                {report.status === 'generating' && (
                  <button className="btn btn-secondary btn-sm" disabled>
                    Generating...
                  </button>
                )}
                {report.status === 'failed' && (
                  <button className="btn btn-secondary btn-sm">
                    Retry
                  </button>
                )}
                <button className="btn btn-secondary btn-sm">
                  View Details
                </button>
                <button className="btn btn-danger btn-sm">
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <div className="modal-overlay" onClick={() => setShowGenerateModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Generate New Report</h2>
              <button className="close-btn" onClick={() => setShowGenerateModal(false)}>
                ×
              </button>
            </div>
            
            <div className="modal-body">
              <div className="form-group">
                <label>Report Type</label>
                <select
                  value={generateForm.type}
                  onChange={(e) => setGenerateForm(prev => ({ ...prev, type: e.target.value }))}
                >
                  <option value="security-summary">Security Summary</option>
                  <option value="vulnerability-analysis">Vulnerability Analysis</option>
                  <option value="compliance">Compliance Audit</option>
                  <option value="dependency-analysis">Dependency Analysis</option>
                  <option value="custom">Custom Report</option>
                </select>
              </div>
              
              <div className="form-group">
                <label>Title</label>
                <input
                  type="text"
                  value={generateForm.title}
                  onChange={(e) => setGenerateForm(prev => ({ ...prev, title: e.target.value }))}
                  placeholder="Enter report title (optional)"
                />
              </div>
              
              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={generateForm.description}
                  onChange={(e) => setGenerateForm(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="Enter report description (optional)"
                  rows={3}
                />
              </div>
              
              <div className="form-group">
                <label>Date Range</label>
                <select
                  value={generateForm.dateRange}
                  onChange={(e) => setGenerateForm(prev => ({ ...prev, dateRange: e.target.value }))}
                >
                  <option value="7d">Last 7 Days</option>
                  <option value="30d">Last 30 Days</option>
                  <option value="90d">Last 90 Days</option>
                  <option value="365d">Last Year</option>
                </select>
              </div>
              
              <div className="form-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={generateForm.includeCharts}
                    onChange={(e) => setGenerateForm(prev => ({ ...prev, includeCharts: e.target.checked }))}
                  />
                  Include Charts and Visualizations
                </label>
              </div>
              
              <div className="form-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={generateForm.includeDetails}
                    onChange={(e) => setGenerateForm(prev => ({ ...prev, includeDetails: e.target.checked }))}
                  />
                  Include Detailed Analysis
                </label>
              </div>
            </div>
            
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowGenerateModal(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleGenerateReport}>
                Generate Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;
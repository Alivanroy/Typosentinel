import React, { useState, useEffect, useMemo } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import './ThreatAnalysis.css';

const ThreatAnalysis = () => {
  const dispatch = useDispatch();
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [filters, setFilters] = useState({
    severity: 'all',
    type: 'all',
    status: 'all',
    package: ''
  });
  const [sortBy, setSortBy] = useState('severity');
  const [sortOrder, setSortOrder] = useState('desc');
  const [searchTerm, setSearchTerm] = useState('');
  const [showDetails, setShowDetails] = useState(false);

  // Mock data for development
  const mockThreats = [
    {
      id: 'THR-001',
      package: 'lodash',
      version: '4.17.20',
      severity: 'high',
      type: 'vulnerability',
      status: 'active',
      title: 'Prototype Pollution in lodash',
      description: 'lodash versions prior to 4.17.21 are vulnerable to Command Injection via template.',
      cve: 'CVE-2021-23337',
      cvss: 7.2,
      publishedDate: '2021-02-15T10:15:00Z',
      discoveredDate: '2024-01-15T14:30:00Z',
      affectedFiles: ['package.json', 'src/utils/helpers.js'],
      recommendation: 'Update to lodash version 4.17.21 or later',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
        'https://github.com/lodash/lodash/commit/c4847ebe7d14540bb28a8b932a9ce1b9f24b08ec'
      ],
      exploitability: 'high',
      impact: 'high',
      vector: 'network'
    },
    {
      id: 'THR-002',
      package: 'axios',
      version: '0.21.0',
      severity: 'medium',
      type: 'vulnerability',
      status: 'mitigated',
      title: 'Regular Expression Denial of Service',
      description: 'Axios versions before 0.21.1 are vulnerable to ReDoS attacks.',
      cve: 'CVE-2020-28168',
      cvss: 5.3,
      publishedDate: '2020-12-08T16:45:00Z',
      discoveredDate: '2024-01-10T09:20:00Z',
      affectedFiles: ['package.json', 'src/services/api.js'],
      recommendation: 'Update to axios version 0.21.1 or later',
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2020-28168'
      ],
      exploitability: 'medium',
      impact: 'medium',
      vector: 'network'
    },
    {
      id: 'THR-003',
      package: 'react-scripts',
      version: '4.0.3',
      severity: 'low',
      type: 'dependency',
      status: 'active',
      title: 'Outdated Development Dependency',
      description: 'react-scripts is using outdated dependencies that may contain security issues.',
      cve: null,
      cvss: 2.1,
      publishedDate: '2021-03-01T12:00:00Z',
      discoveredDate: '2024-01-20T11:15:00Z',
      affectedFiles: ['package.json'],
      recommendation: 'Update to react-scripts version 5.0.0 or later',
      references: [],
      exploitability: 'low',
      impact: 'low',
      vector: 'local'
    }
  ];

  useEffect(() => {
    fetchThreats();
  }, []);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      setThreats(mockThreats);
    } catch (err) {
      setError('Failed to fetch threat analysis data');
      console.error('Error fetching threats:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredAndSortedThreats = useMemo(() => {
    let filtered = threats.filter(threat => {
      const matchesSearch = threat.package.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           threat.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           (threat.cve && threat.cve.toLowerCase().includes(searchTerm.toLowerCase()));
      
      const matchesSeverity = filters.severity === 'all' || threat.severity === filters.severity;
      const matchesType = filters.type === 'all' || threat.type === filters.type;
      const matchesStatus = filters.status === 'all' || threat.status === filters.status;
      const matchesPackage = !filters.package || threat.package.toLowerCase().includes(filters.package.toLowerCase());
      
      return matchesSearch && matchesSeverity && matchesType && matchesStatus && matchesPackage;
    });

    // Sort threats
    filtered.sort((a, b) => {
      let aValue, bValue;
      
      switch (sortBy) {
        case 'severity':
          const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
          aValue = severityOrder[a.severity] || 0;
          bValue = severityOrder[b.severity] || 0;
          break;
        case 'cvss':
          aValue = a.cvss || 0;
          bValue = b.cvss || 0;
          break;
        case 'package':
          aValue = a.package.toLowerCase();
          bValue = b.package.toLowerCase();
          break;
        case 'discoveredDate':
          aValue = new Date(a.discoveredDate);
          bValue = new Date(b.discoveredDate);
          break;
        default:
          aValue = a[sortBy];
          bValue = b[sortBy];
      }
      
      if (sortOrder === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });

    return filtered;
  }, [threats, filters, sortBy, sortOrder, searchTerm]);

  const threatStats = useMemo(() => {
    const stats = {
      total: threats.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      active: 0,
      mitigated: 0
    };
    
    threats.forEach(threat => {
      stats[threat.severity]++;
      stats[threat.status]++;
    });
    
    return stats;
  }, [threats]);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#d97706';
      case 'low': return '#65a30d';
      default: return '#6b7280';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return '#dc2626';
      case 'mitigated': return '#059669';
      case 'investigating': return '#d97706';
      case 'resolved': return '#065f46';
      default: return '#6b7280';
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const handleThreatClick = (threat) => {
    setSelectedThreat(threat);
    setShowDetails(true);
  };

  const handleFilterChange = (filterType, value) => {
    setFilters(prev => ({
      ...prev,
      [filterType]: value
    }));
  };

  const clearFilters = () => {
    setFilters({
      severity: 'all',
      type: 'all',
      status: 'all',
      package: ''
    });
    setSearchTerm('');
  };

  if (loading) {
    return (
      <div className="threat-analysis">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading threat analysis...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="threat-analysis">
        <div className="error-container">
          <div className="error-icon">⚠️</div>
          <h3>Error Loading Threats</h3>
          <p>{error}</p>
          <button className="retry-btn" onClick={fetchThreats}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="threat-analysis">
      <div className="threat-analysis-header">
        <div className="header-content">
          <h1>Threat Analysis</h1>
          <div className="threat-stats">
            <div className="stat">
              <div className="stat-value">{threatStats.total}</div>
              <div className="stat-label">Total Threats</div>
            </div>
            <div className="stat">
              <div className="stat-value" style={{ color: getSeverityColor('critical') }}>
                {threatStats.critical}
              </div>
              <div className="stat-label">Critical</div>
            </div>
            <div className="stat">
              <div className="stat-value" style={{ color: getSeverityColor('high') }}>
                {threatStats.high}
              </div>
              <div className="stat-label">High</div>
            </div>
            <div className="stat">
              <div className="stat-value" style={{ color: getSeverityColor('medium') }}>
                {threatStats.medium}
              </div>
              <div className="stat-label">Medium</div>
            </div>
            <div className="stat">
              <div className="stat-value" style={{ color: getSeverityColor('low') }}>
                {threatStats.low}
              </div>
              <div className="stat-label">Low</div>
            </div>
          </div>
        </div>
      </div>

      <div className="threat-controls">
        <div className="search-box">
          <input
            type="text"
            className="search-input"
            placeholder="Search threats by package, title, or CVE..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        
        <div className="filter-controls">
          <select
            className="filter-select"
            value={filters.severity}
            onChange={(e) => handleFilterChange('severity', e.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          
          <select
            className="filter-select"
            value={filters.type}
            onChange={(e) => handleFilterChange('type', e.target.value)}
          >
            <option value="all">All Types</option>
            <option value="vulnerability">Vulnerability</option>
            <option value="dependency">Dependency</option>
            <option value="malware">Malware</option>
            <option value="license">License</option>
          </select>
          
          <select
            className="filter-select"
            value={filters.status}
            onChange={(e) => handleFilterChange('status', e.target.value)}
          >
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="mitigated">Mitigated</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
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
            <option value="severity-desc">Severity (High to Low)</option>
            <option value="severity-asc">Severity (Low to High)</option>
            <option value="cvss-desc">CVSS Score (High to Low)</option>
            <option value="cvss-asc">CVSS Score (Low to High)</option>
            <option value="package-asc">Package (A to Z)</option>
            <option value="package-desc">Package (Z to A)</option>
            <option value="discoveredDate-desc">Recently Discovered</option>
            <option value="discoveredDate-asc">Oldest First</option>
          </select>
          
          <button className="clear-filters-btn" onClick={clearFilters}>
            Clear Filters
          </button>
        </div>
      </div>

      {filteredAndSortedThreats.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">🔍</div>
          <h3>No Threats Found</h3>
          <p>No threats match your current search and filter criteria.</p>
        </div>
      ) : (
        <div className="threat-list">
          {filteredAndSortedThreats.map(threat => (
            <div key={threat.id} className="threat-card" onClick={() => handleThreatClick(threat)}>
              <div className="threat-card-header">
                <div className="threat-info">
                  <h3>{threat.title}</h3>
                  <div className="threat-meta">
                    <span className="threat-id">{threat.id}</span>
                    <span className="threat-package">{threat.package}@{threat.version}</span>
                    {threat.cve && <span className="threat-cve">{threat.cve}</span>}
                  </div>
                </div>
                <div className="threat-badges">
                  <span 
                    className="severity-badge"
                    style={{ backgroundColor: getSeverityColor(threat.severity) }}
                  >
                    {threat.severity}
                  </span>
                  <span 
                    className="status-badge"
                    style={{ backgroundColor: getStatusColor(threat.status) }}
                  >
                    {threat.status}
                  </span>
                </div>
              </div>
              
              <div className="threat-card-body">
                <p className="threat-description">{threat.description}</p>
                
                <div className="threat-metrics">
                  <div className="metric">
                    <div className="metric-label">CVSS Score</div>
                    <div className="metric-value">{threat.cvss || 'N/A'}</div>
                  </div>
                  <div className="metric">
                    <div className="metric-label">Type</div>
                    <div className="metric-value">{threat.type}</div>
                  </div>
                  <div className="metric">
                    <div className="metric-label">Discovered</div>
                    <div className="metric-value">{formatDate(threat.discoveredDate)}</div>
                  </div>
                  <div className="metric">
                    <div className="metric-label">Affected Files</div>
                    <div className="metric-value">{threat.affectedFiles.length}</div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Threat Details Modal */}
      {showDetails && selectedThreat && (
        <div className="threat-modal-overlay" onClick={() => setShowDetails(false)}>
          <div className="threat-modal" onClick={(e) => e.stopPropagation()}>
            <div className="threat-modal-header">
              <h2>{selectedThreat.title}</h2>
              <button className="close-btn" onClick={() => setShowDetails(false)}>
                ×
              </button>
            </div>
            
            <div className="threat-modal-body">
              <div className="threat-overview">
                <div className="overview-item">
                  <strong>Package:</strong> {selectedThreat.package}@{selectedThreat.version}
                </div>
                <div className="overview-item">
                  <strong>Threat ID:</strong> {selectedThreat.id}
                </div>
                {selectedThreat.cve && (
                  <div className="overview-item">
                    <strong>CVE:</strong> {selectedThreat.cve}
                  </div>
                )}
                <div className="overview-item">
                  <strong>CVSS Score:</strong> {selectedThreat.cvss || 'N/A'}
                </div>
                <div className="overview-item">
                  <strong>Severity:</strong> 
                  <span 
                    className="severity-badge"
                    style={{ backgroundColor: getSeverityColor(selectedThreat.severity) }}
                  >
                    {selectedThreat.severity}
                  </span>
                </div>
                <div className="overview-item">
                  <strong>Status:</strong> 
                  <span 
                    className="status-badge"
                    style={{ backgroundColor: getStatusColor(selectedThreat.status) }}
                  >
                    {selectedThreat.status}
                  </span>
                </div>
              </div>
              
              <div className="threat-section">
                <h3>Description</h3>
                <p>{selectedThreat.description}</p>
              </div>
              
              <div className="threat-section">
                <h3>Recommendation</h3>
                <p>{selectedThreat.recommendation}</p>
              </div>
              
              <div className="threat-section">
                <h3>Affected Files</h3>
                <ul className="affected-files-list">
                  {selectedThreat.affectedFiles.map((file, index) => (
                    <li key={index} className="affected-file">{file}</li>
                  ))}
                </ul>
              </div>
              
              {selectedThreat.references.length > 0 && (
                <div className="threat-section">
                  <h3>References</h3>
                  <ul className="references-list">
                    {selectedThreat.references.map((ref, index) => (
                      <li key={index}>
                        <a href={ref} target="_blank" rel="noopener noreferrer">
                          {ref}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              
              <div className="threat-section">
                <h3>Risk Assessment</h3>
                <div className="risk-grid">
                  <div className="risk-item">
                    <strong>Exploitability:</strong> {selectedThreat.exploitability}
                  </div>
                  <div className="risk-item">
                    <strong>Impact:</strong> {selectedThreat.impact}
                  </div>
                  <div className="risk-item">
                    <strong>Attack Vector:</strong> {selectedThreat.vector}
                  </div>
                  <div className="risk-item">
                    <strong>Published:</strong> {formatDate(selectedThreat.publishedDate)}
                  </div>
                </div>
              </div>
            </div>
            
            <div className="threat-modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowDetails(false)}>
                Close
              </button>
              <button className="btn btn-primary">
                Mark as Mitigated
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ThreatAnalysis;
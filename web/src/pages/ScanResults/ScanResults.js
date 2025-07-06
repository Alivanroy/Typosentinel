import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { getScanResults, deleteScan } from '../../store/slices/scanSlice';
import './ScanResults.css';

const ScanResults = () => {
  const dispatch = useDispatch();
  const { scanResults, loading, error } = useSelector(state => state.scan);
  const scans = scanResults?.data || [];
  const [filter, setFilter] = useState('all');
  const [sortBy, setSortBy] = useState('date');
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    dispatch(getScanResults({ page: 1, limit: 20, filters: {} }));
  }, [dispatch]);


  const handleDeleteScan = (scanId) => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      dispatch(deleteScan(scanId));
    }
  };

  const filteredScans = scans
    .filter(scan => {
      if (filter === 'all') return true;
      return scan.status === filter;
    })
    .filter(scan => 
      scan.target?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      scan.id?.toString().includes(searchTerm)
    )
    .sort((a, b) => {
      switch (sortBy) {
        case 'date':
          return new Date(b.createdAt) - new Date(a.createdAt);
        case 'target':
          return (a.target || '').localeCompare(b.target || '');
        case 'threats':
          return (b.threatsFound || 0) - (a.threatsFound || 0);
        default:
          return 0;
      }
    });

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return '#10b981';
      case 'running': return '#f59e0b';
      case 'failed': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getThreatLevelColor = (level) => {
    switch (level) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#d97706';
      case 'low': return '#65a30d';
      default: return '#6b7280';
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const formatDuration = (startTime, endTime) => {
    if (!endTime) return 'Running...';
    const duration = new Date(endTime) - new Date(startTime);
    const seconds = Math.floor(duration / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  if (loading) {
    return (
      <div className="scan-results">
        <div className="scan-results-header">
          <h1>Scan Results</h1>
        </div>
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading scan results...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="scan-results">
        <div className="scan-results-header">
          <h1>Scan Results</h1>
        </div>
        <div className="error-container">
          <div className="error-icon">⚠️</div>
          <h3>Error Loading Scans</h3>
          <p>{error}</p>
          <button 
            className="retry-btn"
            onClick={() => dispatch(getScanResults({ page: 1, limit: 20, filters: {} }))}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="scan-results">
      <div className="scan-results-header">
        <h1>Scan Results</h1>
        <div className="scan-stats">
          <div className="stat">
            <span className="stat-value">{scans.length}</span>
            <span className="stat-label">Total Scans</span>
          </div>
          <div className="stat">
            <span className="stat-value">
              {scans.filter(s => s.status === 'completed').length}
            </span>
            <span className="stat-label">Completed</span>
          </div>
          <div className="stat">
            <span className="stat-value">
              {scans.reduce((sum, s) => sum + (s.threatsFound || 0), 0)}
            </span>
            <span className="stat-label">Threats Found</span>
          </div>
        </div>
      </div>

      <div className="scan-controls">
        <div className="search-box">
          <input
            type="text"
            placeholder="Search scans..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>
        
        <div className="filter-controls">
          <select 
            value={filter} 
            onChange={(e) => setFilter(e.target.value)}
            className="filter-select"
          >
            <option value="all">All Status</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="failed">Failed</option>
          </select>
          
          <select 
            value={sortBy} 
            onChange={(e) => setSortBy(e.target.value)}
            className="sort-select"
          >
            <option value="date">Sort by Date</option>
            <option value="target">Sort by Target</option>
            <option value="threats">Sort by Threats</option>
          </select>
        </div>
      </div>

      <div className="scan-list">
        {filteredScans.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">🔍</div>
            <h3>No Scans Found</h3>
            <p>
              {searchTerm || filter !== 'all' 
                ? 'No scans match your current filters.' 
                : 'No scans have been performed yet.'}
            </p>
          </div>
        ) : (
          filteredScans.map(scan => (
            <div key={scan.id} className="scan-card">
              <div className="scan-card-header">
                <div className="scan-info">
                  <h3 className="scan-target">{scan.target || 'Unknown Target'}</h3>
                  <div className="scan-meta">
                    <span className="scan-id">ID: {scan.id}</span>
                    <span className="scan-date">{formatDate(scan.createdAt)}</span>
                  </div>
                </div>
                <div className="scan-status">
                  <span 
                    className="status-badge"
                    style={{ backgroundColor: getStatusColor(scan.status) }}
                  >
                    {scan.status}
                  </span>
                </div>
              </div>

              <div className="scan-card-body">
                <div className="scan-metrics">
                  <div className="metric">
                    <span className="metric-label">Duration</span>
                    <span className="metric-value">
                      {formatDuration(scan.createdAt, scan.completedAt)}
                    </span>
                  </div>
                  <div className="metric">
                    <span className="metric-label">Packages Scanned</span>
                    <span className="metric-value">{scan.packagesScanned || 0}</span>
                  </div>
                  <div className="metric">
                    <span className="metric-label">Threats Found</span>
                    <span className="metric-value threat-count">
                      {scan.threatsFound || 0}
                    </span>
                  </div>
                </div>

                {scan.threats && scan.threats.length > 0 && (
                  <div className="threat-summary">
                    <h4>Top Threats</h4>
                    <div className="threat-list">
                      {scan.threats.slice(0, 3).map((threat, index) => (
                        <div key={index} className="threat-item">
                          <span 
                            className="threat-level"
                            style={{ color: getThreatLevelColor(threat.level) }}
                          >
                            {threat.level}
                          </span>
                          <span className="threat-package">{threat.package}</span>
                          <span className="threat-type">{threat.type}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="scan-card-actions">
                <button 
                  className="btn btn-primary"
                  onClick={() => window.open(`/scans/${scan.id}`, '_blank')}
                >
                  View Details
                </button>
                <button 
                  className="btn btn-secondary"
                  onClick={() => window.open(`/scans/${scan.id}/report`, '_blank')}
                >
                  Download Report
                </button>
                <button 
                  className="btn btn-danger"
                  onClick={() => handleDeleteScan(scan.id)}
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default ScanResults;
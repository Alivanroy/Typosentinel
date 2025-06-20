import React, { useState, useEffect } from 'react';
import './ActivityFeed.css';

const ActivityFeed = ({ 
  activities = [], 
  loading = false, 
  onRefresh, 
  maxItems = 10,
  showFilters = true,
  autoRefresh = false,
  refreshInterval = 30000
}) => {
  const [filter, setFilter] = useState('all');
  const [expandedItems, setExpandedItems] = useState(new Set());
  const [refreshTimer, setRefreshTimer] = useState(null);

  useEffect(() => {
    if (autoRefresh && onRefresh) {
      const timer = setInterval(onRefresh, refreshInterval);
      setRefreshTimer(timer);
      return () => clearInterval(timer);
    }
  }, [autoRefresh, refreshInterval, onRefresh]);

  const filteredActivities = activities
    .filter(activity => filter === 'all' || activity.type === filter)
    .slice(0, maxItems);

  const toggleExpanded = (id) => {
    const newExpanded = new Set(expandedItems);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedItems(newExpanded);
  };

  const getActivityIcon = (type, severity) => {
    switch (type) {
      case 'scan_completed':
        return '✅';
      case 'scan_started':
        return '🔍';
      case 'threat_detected':
        return severity === 'critical' ? '🚨' : severity === 'high' ? '⚠️' : '💡';
      case 'threat_resolved':
        return '✅';
      case 'system_alert':
        return '🔔';
      case 'user_action':
        return '👤';
      case 'config_change':
        return '⚙️';
      case 'error':
        return '❌';
      default:
        return '📝';
    }
  };

  const getActivityColor = (type, severity) => {
    switch (type) {
      case 'threat_detected':
        switch (severity) {
          case 'critical': return '#dc2626';
          case 'high': return '#ea580c';
          case 'medium': return '#d97706';
          case 'low': return '#16a34a';
          default: return '#6b7280';
        }
      case 'scan_completed':
      case 'threat_resolved':
        return '#16a34a';
      case 'error':
        return '#dc2626';
      case 'system_alert':
        return '#f59e0b';
      default:
        return '#3b82f6';
    }
  };

  const formatTimeAgo = (timestamp) => {
    const now = new Date();
    const time = new Date(timestamp);
    const diffInSeconds = Math.floor((now - time) / 1000);

    if (diffInSeconds < 60) {
      return 'Just now';
    } else if (diffInSeconds < 3600) {
      const minutes = Math.floor(diffInSeconds / 60);
      return `${minutes}m ago`;
    } else if (diffInSeconds < 86400) {
      const hours = Math.floor(diffInSeconds / 3600);
      return `${hours}h ago`;
    } else {
      const days = Math.floor(diffInSeconds / 86400);
      return `${days}d ago`;
    }
  };

  const filterOptions = [
    { value: 'all', label: 'All Activities', count: activities.length },
    { value: 'threat_detected', label: 'Threats', count: activities.filter(a => a.type === 'threat_detected').length },
    { value: 'scan_completed', label: 'Scans', count: activities.filter(a => a.type === 'scan_completed').length },
    { value: 'system_alert', label: 'Alerts', count: activities.filter(a => a.type === 'system_alert').length },
    { value: 'user_action', label: 'User Actions', count: activities.filter(a => a.type === 'user_action').length },
  ];

  if (loading && activities.length === 0) {
    return (
      <div className="activity-feed">
        <div className="activity-header">
          <h3>Recent Activity</h3>
        </div>
        <div className="activity-list">
          {Array.from({ length: 5 }).map((_, index) => (
            <div key={index} className="activity-item skeleton">
              <div className="activity-icon skeleton-circle" />
              <div className="activity-content">
                <div className="skeleton-text skeleton-title" />
                <div className="skeleton-text skeleton-subtitle" />
                <div className="skeleton-text skeleton-time" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="activity-feed">
      <div className="activity-header">
        <h3>Recent Activity</h3>
        <div className="activity-controls">
          {onRefresh && (
            <button 
              className="refresh-btn"
              onClick={onRefresh}
              disabled={loading}
              title="Refresh activities"
            >
              {loading ? '🔄' : '↻'}
            </button>
          )}
        </div>
      </div>

      {showFilters && (
        <div className="activity-filters">
          {filterOptions.map(option => (
            <button
              key={option.value}
              className={`filter-btn ${filter === option.value ? 'active' : ''}`}
              onClick={() => setFilter(option.value)}
            >
              {option.label}
              {option.count > 0 && (
                <span className="filter-count">{option.count}</span>
              )}
            </button>
          ))}
        </div>
      )}

      <div className="activity-list">
        {filteredActivities.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">📭</div>
            <div className="empty-title">No activities found</div>
            <div className="empty-subtitle">
              {filter === 'all' 
                ? 'No recent activities to display'
                : `No ${filterOptions.find(f => f.value === filter)?.label.toLowerCase()} to display`
              }
            </div>
          </div>
        ) : (
          filteredActivities.map((activity, index) => {
            const isExpanded = expandedItems.has(activity.id);
            const hasDetails = activity.details && Object.keys(activity.details).length > 0;
            
            return (
              <div 
                key={activity.id || index} 
                className={`activity-item ${activity.type} ${activity.severity || ''}`}
              >
                <div 
                  className="activity-icon"
                  style={{ 
                    backgroundColor: `${getActivityColor(activity.type, activity.severity)}20`,
                    color: getActivityColor(activity.type, activity.severity)
                  }}
                >
                  {getActivityIcon(activity.type, activity.severity)}
                </div>
                
                <div className="activity-content">
                  <div className="activity-main">
                    <div className="activity-title">
                      {activity.title || activity.message}
                    </div>
                    
                    <div className="activity-meta">
                      <span className="activity-time">
                        {formatTimeAgo(activity.timestamp)}
                      </span>
                      
                      {activity.source && (
                        <span className="activity-source">
                          • {activity.source}
                        </span>
                      )}
                      
                      {activity.severity && (
                        <span className={`activity-severity ${activity.severity}`}>
                          • {activity.severity.toUpperCase()}
                        </span>
                      )}
                    </div>
                    
                    {activity.description && (
                      <div className="activity-description">
                        {activity.description}
                      </div>
                    )}
                  </div>
                  
                  {hasDetails && (
                    <button
                      className="expand-btn"
                      onClick={() => toggleExpanded(activity.id)}
                      title={isExpanded ? 'Show less' : 'Show more'}
                    >
                      {isExpanded ? '▼' : '▶'}
                    </button>
                  )}
                </div>
                
                {isExpanded && hasDetails && (
                  <div className="activity-details">
                    {Object.entries(activity.details).map(([key, value]) => (
                      <div key={key} className="detail-item">
                        <span className="detail-key">{key}:</span>
                        <span className="detail-value">
                          {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
      
      {activities.length > maxItems && (
        <div className="activity-footer">
          <button className="view-all-btn">
            View All Activities ({activities.length})
          </button>
        </div>
      )}
    </div>
  );
};

export default ActivityFeed;
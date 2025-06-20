import React from 'react';
import './MetricCard.css';

const MetricCard = ({
  title,
  value,
  icon,
  color = '#3b82f6',
  trend,
  trendDirection = 'up',
  loading = false,
  onClick,
  subtitle,
  formatter,
}) => {
  const formatValue = (val) => {
    if (formatter && typeof formatter === 'function') {
      return formatter(val);
    }
    
    if (typeof val === 'number') {
      if (val >= 1000000) {
        return `${(val / 1000000).toFixed(1)}M`;
      } else if (val >= 1000) {
        return `${(val / 1000).toFixed(1)}K`;
      }
      return val.toLocaleString();
    }
    
    return val || '0';
  };

  const getTrendIcon = () => {
    switch (trendDirection) {
      case 'up':
        return '↗️';
      case 'down':
        return '↘️';
      case 'neutral':
        return '➡️';
      default:
        return '↗️';
    }
  };

  const getTrendClass = () => {
    switch (trendDirection) {
      case 'up':
        return 'trend-up';
      case 'down':
        return 'trend-down';
      case 'neutral':
        return 'trend-neutral';
      default:
        return 'trend-up';
    }
  };

  return (
    <div 
      className={`metric-card ${loading ? 'loading' : ''} ${onClick ? 'clickable' : ''}`}
      onClick={onClick}
      style={{
        '--metric-color': color,
      }}
    >
      {loading && <div className="loading-overlay" />}
      
      <div className="metric-header">
        <div className="metric-icon" style={{ backgroundColor: `${color}20` }}>
          <span style={{ color }}>{icon}</span>
        </div>
        
        {trend && (
          <div className={`metric-trend ${getTrendClass()}`}>
            <span className="trend-icon">{getTrendIcon()}</span>
            <span className="trend-value">{trend}</span>
          </div>
        )}
      </div>
      
      <div className="metric-content">
        <div className="metric-value">
          {loading ? (
            <div className="skeleton-text skeleton-value" />
          ) : (
            formatValue(value)
          )}
        </div>
        
        <div className="metric-title">
          {loading ? (
            <div className="skeleton-text skeleton-title" />
          ) : (
            title
          )}
        </div>
        
        {subtitle && (
          <div className="metric-subtitle">
            {loading ? (
              <div className="skeleton-text skeleton-subtitle" />
            ) : (
              subtitle
            )}
          </div>
        )}
      </div>
      
      <div className="metric-accent" style={{ backgroundColor: color }} />
    </div>
  );
};

// Specialized metric card variants
export const ThreatMetricCard = ({ threats, ...props }) => {
  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return '#dc2626';
      case 'high':
        return '#ea580c';
      case 'medium':
        return '#d97706';
      case 'low':
        return '#16a34a';
      default:
        return '#6b7280';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return '🚨';
      case 'high':
        return '⚠️';
      case 'medium':
        return '⚡';
      case 'low':
        return '💡';
      default:
        return '🔍';
    }
  };

  return (
    <MetricCard
      {...props}
      value={threats?.count || 0}
      icon={getSeverityIcon(threats?.severity)}
      color={getSeverityColor(threats?.severity)}
      subtitle={`${threats?.severity || 'Unknown'} Severity`}
    />
  );
};

export const PerformanceMetricCard = ({ metric, unit = '', ...props }) => {
  const getPerformanceColor = (value, thresholds) => {
    if (!thresholds) return '#3b82f6';
    
    if (value <= thresholds.good) return '#16a34a';
    if (value <= thresholds.warning) return '#d97706';
    return '#dc2626';
  };

  const formatPerformanceValue = (value) => {
    if (unit === 'ms' && value >= 1000) {
      return `${(value / 1000).toFixed(1)}s`;
    }
    if (unit === 'bytes') {
      if (value >= 1024 * 1024 * 1024) {
        return `${(value / (1024 * 1024 * 1024)).toFixed(1)}GB`;
      }
      if (value >= 1024 * 1024) {
        return `${(value / (1024 * 1024)).toFixed(1)}MB`;
      }
      if (value >= 1024) {
        return `${(value / 1024).toFixed(1)}KB`;
      }
      return `${value}B`;
    }
    return `${value}${unit}`;
  };

  return (
    <MetricCard
      {...props}
      value={metric?.value || 0}
      color={getPerformanceColor(metric?.value, metric?.thresholds)}
      formatter={formatPerformanceValue}
    />
  );
};

export const StatusMetricCard = ({ status, ...props }) => {
  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'healthy':
      case 'online':
      case 'active':
      case 'success':
        return '#16a34a';
      case 'warning':
      case 'degraded':
        return '#d97706';
      case 'error':
      case 'offline':
      case 'failed':
      case 'critical':
        return '#dc2626';
      default:
        return '#6b7280';
    }
  };

  const getStatusIcon = (status) => {
    switch (status?.toLowerCase()) {
      case 'healthy':
      case 'online':
      case 'active':
      case 'success':
        return '✅';
      case 'warning':
      case 'degraded':
        return '⚠️';
      case 'error':
      case 'offline':
      case 'failed':
      case 'critical':
        return '❌';
      default:
        return '❓';
    }
  };

  return (
    <MetricCard
      {...props}
      value={status || 'Unknown'}
      icon={getStatusIcon(status)}
      color={getStatusColor(status)}
      formatter={(val) => val.charAt(0).toUpperCase() + val.slice(1)}
    />
  );
};

export default MetricCard;
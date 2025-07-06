import React, { useMemo } from 'react';
import './ThreatChart.css';

const ThreatChart = ({ data = [], loading = false, timeRange = '7d', height = 300 }) => {
  const chartData = useMemo(() => {
    if (!data || data.length === 0) {
      return generateMockData(timeRange);
    }
    return data;
  }, [data, timeRange]);

  const { maxValue, chartPoints, labels } = useMemo(() => {
    if (!chartData || chartData.length === 0) {
      return { maxValue: 100, chartPoints: [], labels: [] };
    }

    const severityTypes = ['critical', 'high', 'medium', 'low'];
    const maxVal = Math.max(
      ...chartData.map(item => 
        severityTypes.reduce((sum, severity) => sum + (item[severity] || 0), 0)
      )
    );
    
    const points = severityTypes.map(severity => {
      return chartData.map((item, index) => {
        // Handle single data point case to avoid division by zero
        const x = chartData.length === 1 ? 50 : (index / (chartData.length - 1)) * 100;
        const y = maxVal === 0 ? 100 : 100 - ((item[severity] || 0) / maxVal) * 100;
        return { x: isNaN(x) ? 0 : x, y: isNaN(y) ? 100 : y, value: item[severity] || 0 };
      });
    });

    const chartLabels = chartData.map(item => {
      const date = new Date(item.date || item.timestamp);
      return formatDateLabel(date, timeRange);
    });

    return {
      maxValue: maxVal,
      chartPoints: points,
      labels: chartLabels
    };
  }, [chartData, timeRange]);

  const severityConfig = {
    critical: { color: '#ef4444', name: 'Critical' },
    high: { color: '#f59e0b', name: 'High' },
    medium: { color: '#eab308', name: 'Medium' },
    low: { color: '#22c55e', name: 'Low' }
  };

  const generatePath = (points) => {
    if (points.length === 0) return '';
    
    let path = `M ${points[0].x} ${points[0].y}`;
    
    for (let i = 1; i < points.length; i++) {
      const prev = points[i - 1];
      const curr = points[i];
      const cpx1 = prev.x + (curr.x - prev.x) * 0.3;
      const cpy1 = prev.y;
      const cpx2 = curr.x - (curr.x - prev.x) * 0.3;
      const cpy2 = curr.y;
      
      path += ` C ${cpx1} ${cpy1}, ${cpx2} ${cpy2}, ${curr.x} ${curr.y}`;
    }
    
    return path;
  };

  const generateAreaPath = (points) => {
    if (points.length === 0) return '';
    
    const linePath = generatePath(points);
    const lastPoint = points[points.length - 1];
    const firstPoint = points[0];
    
    return `${linePath} L ${lastPoint.x} 100 L ${firstPoint.x} 100 Z`;
  };

  if (loading) {
    return (
      <div className="threat-chart loading" style={{ height }}>
        <div className="chart-skeleton">
          <div className="skeleton-line" />
          <div className="skeleton-line" />
          <div className="skeleton-line" />
          <div className="skeleton-bars">
            {Array.from({ length: 7 }).map((_, i) => (
              <div key={i} className="skeleton-bar" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="threat-chart" style={{ height }}>
      <div className="chart-container">
        <svg
          width="100%"
          height="100%"
          viewBox="0 0 100 100"
          preserveAspectRatio="none"
          className="chart-svg"
        >
          {/* Grid Lines */}
          <defs>
            <pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse">
              <path d="M 10 0 L 0 0 0 10" fill="none" stroke="#e2e8f0" strokeWidth="0.1" />
            </pattern>
          </defs>
          <rect width="100" height="100" fill="url(#grid)" />
          
          {/* Y-axis labels */}
          {[0, 25, 50, 75, 100].map(y => (
            <g key={y}>
              <line
                x1="0"
                y1={100 - y}
                x2="100"
                y2={100 - y}
                stroke="#f1f5f9"
                strokeWidth="0.1"
              />
            </g>
          ))}
          
          {/* Area Charts */}
          {Object.entries(severityConfig).map(([severity, config], index) => {
            const points = chartPoints[index] || [];
            if (points.length === 0) return null;
            
            return (
              <g key={severity}>
                <path
                  d={generateAreaPath(points)}
                  fill={`${config.color}20`}
                  className="chart-area"
                />
                <path
                  d={generatePath(points)}
                  fill="none"
                  stroke={config.color}
                  strokeWidth="0.3"
                  className="chart-line"
                />
                {/* Data Points */}
                {points.map((point, pointIndex) => (
                  <circle
                    key={pointIndex}
                    cx={point.x}
                    cy={point.y}
                    r="0.5"
                    fill={config.color}
                    className="chart-point"
                    data-value={point.value}
                    data-severity={severity}
                    data-date={labels[pointIndex]}
                  />
                ))}
              </g>
            );
          })}
        </svg>
        
        {/* Tooltip */}
        <div className="chart-tooltip" id="chart-tooltip">
          <div className="tooltip-content">
            <div className="tooltip-date"></div>
            <div className="tooltip-values"></div>
          </div>
        </div>
      </div>
      
      {/* X-axis Labels */}
      <div className="chart-labels">
        {labels.map((label, index) => {
          const shouldShow = labels.length <= 7 || index % Math.ceil(labels.length / 7) === 0;
          // Handle single label case to avoid division by zero
          const leftPosition = labels.length === 1 ? 50 : (index / (labels.length - 1)) * 100;
          return shouldShow ? (
            <div
              key={index}
              className="chart-label"
              style={{ left: `${leftPosition}%` }}
            >
              {label}
            </div>
          ) : null;
        })}
      </div>
      
      {/* Y-axis Labels */}
      <div className="chart-y-labels">
        {[0, 25, 50, 75, 100].map(percentage => {
          const value = Math.round((percentage / 100) * maxValue);
          return (
            <div
              key={percentage}
              className="chart-y-label"
              style={{ bottom: `${percentage}%` }}
            >
              {value}
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Helper Functions
const formatDateLabel = (date, timeRange) => {
  if (!date || isNaN(date.getTime())) {
    return '';
  }
  
  switch (timeRange) {
    case '1d':
      return date.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit',
        hour12: false 
      });
    case '7d':
      return date.toLocaleDateString('en-US', { 
        weekday: 'short',
        month: 'short',
        day: 'numeric'
      });
    case '30d':
    case '90d':
      return date.toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric' 
      });
    default:
      return date.toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric' 
      });
  }
};

const generateMockData = (timeRange) => {
  const now = new Date();
  const dataPoints = {
    '1d': 24,
    '7d': 7,
    '30d': 30,
    '90d': 90
  }[timeRange] || 7;
  
  const interval = {
    '1d': 60 * 60 * 1000, // 1 hour
    '7d': 24 * 60 * 60 * 1000, // 1 day
    '30d': 24 * 60 * 60 * 1000, // 1 day
    '90d': 24 * 60 * 60 * 1000 // 1 day
  }[timeRange] || 24 * 60 * 60 * 1000;
  
  return Array.from({ length: dataPoints }, (_, i) => {
    const date = new Date(now.getTime() - (dataPoints - 1 - i) * interval);
    return {
      date: date.toISOString(),
      critical: Math.floor(Math.random() * 5),
      high: Math.floor(Math.random() * 10),
      medium: Math.floor(Math.random() * 15),
      low: Math.floor(Math.random() * 20)
    };
  });
};

export default ThreatChart;
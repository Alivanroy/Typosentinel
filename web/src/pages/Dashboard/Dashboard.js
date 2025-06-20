import React, { useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
  getDashboardMetrics,
  getRecentActivity,
  getThreatTrends,
  setSelectedTimeRange,
} from '../../store/slices/dashboardSlice';
import MetricCard from '../../components/MetricCard/MetricCard';
import ThreatChart from '../../components/Charts/ThreatChart';
import ActivityFeed from '../../components/ActivityFeed/ActivityFeed';
import './Dashboard.css';

const Dashboard = () => {
  const dispatch = useDispatch();
  const {
    metrics,
    recentActivity,
    threatTrends,
    loading,
    selectedTimeRange,
    autoRefresh,
    refreshInterval,
  } = useSelector(state => state.dashboard);

  const [refreshTimer, setRefreshTimer] = useState(null);

  useEffect(() => {
    // Initial data fetch
    fetchDashboardData();

    // Set up auto-refresh if enabled
    if (autoRefresh) {
      const timer = setInterval(() => {
        fetchDashboardData();
      }, refreshInterval);
      setRefreshTimer(timer);
    }

    return () => {
      if (refreshTimer) {
        clearInterval(refreshTimer);
      }
    };
  }, [selectedTimeRange, autoRefresh, refreshInterval]);

  const fetchDashboardData = () => {
    dispatch(getDashboardMetrics(selectedTimeRange));
    dispatch(getRecentActivity(10));
    dispatch(getThreatTrends(selectedTimeRange));
  };

  const handleTimeRangeChange = (timeRange) => {
    dispatch(setSelectedTimeRange(timeRange));
  };

  const handleRefresh = () => {
    fetchDashboardData();
  };

  const timeRangeOptions = [
    { value: '1d', label: 'Last 24 Hours' },
    { value: '7d', label: 'Last 7 Days' },
    { value: '30d', label: 'Last 30 Days' },
    { value: '90d', label: 'Last 90 Days' },
  ];

  const metricCards = [
    {
      title: 'Total Scans',
      value: metrics.totalScans,
      icon: '🔍',
      color: '#3b82f6',
      trend: '+12%',
      trendDirection: 'up',
    },
    {
      title: 'Threats Detected',
      value: metrics.threatsDetected,
      icon: '⚠️',
      color: '#ef4444',
      trend: '+8%',
      trendDirection: 'up',
    },
    {
      title: 'Critical Threats',
      value: metrics.criticalThreats,
      icon: '🚨',
      color: '#dc2626',
      trend: '-5%',
      trendDirection: 'down',
    },
    {
      title: 'Packages Scanned',
      value: metrics.packagesScanned,
      icon: '📦',
      color: '#10b981',
      trend: '+15%',
      trendDirection: 'up',
    },
    {
      title: 'Success Rate',
      value: `${metrics.scanSuccessRate}%`,
      icon: '✅',
      color: '#059669',
      trend: '+2%',
      trendDirection: 'up',
    },
    {
      title: 'Avg Scan Time',
      value: `${metrics.averageScanTime}s`,
      icon: '⏱️',
      color: '#8b5cf6',
      trend: '-10%',
      trendDirection: 'down',
    },
  ];

  return (
    <div className="dashboard">
      {/* Dashboard Header */}
      <div className="dashboard-header">
        <div className="dashboard-title">
          <h1>Security Dashboard</h1>
          <p>Monitor your application security in real-time</p>
        </div>
        
        <div className="dashboard-controls">
          <select
            className="time-range-select"
            value={selectedTimeRange}
            onChange={(e) => handleTimeRangeChange(e.target.value)}
          >
            {timeRangeOptions.map(option => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          
          <button
            className="refresh-btn"
            onClick={handleRefresh}
            disabled={loading.metrics}
          >
            {loading.metrics ? '🔄' : '↻'} Refresh
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="metrics-grid">
        {metricCards.map((metric, index) => (
          <MetricCard
            key={index}
            title={metric.title}
            value={metric.value}
            icon={metric.icon}
            color={metric.color}
            trend={metric.trend}
            trendDirection={metric.trendDirection}
            loading={loading.metrics}
          />
        ))}
      </div>

      {/* Charts and Activity */}
      <div className="dashboard-content">
        <div className="charts-section">
          <div className="chart-container">
            <div className="chart-header">
              <h3>Threat Trends</h3>
              <div className="chart-legend">
                <div className="legend-item">
                  <div className="legend-color" style={{ backgroundColor: '#ef4444' }}></div>
                  <span>Critical</span>
                </div>
                <div className="legend-item">
                  <div className="legend-color" style={{ backgroundColor: '#f59e0b' }}></div>
                  <span>High</span>
                </div>
                <div className="legend-item">
                  <div className="legend-color" style={{ backgroundColor: '#eab308' }}></div>
                  <span>Medium</span>
                </div>
                <div className="legend-item">
                  <div className="legend-color" style={{ backgroundColor: '#22c55e' }}></div>
                  <span>Low</span>
                </div>
              </div>
            </div>
            <ThreatChart
              data={threatTrends.daily}
              loading={loading.trends}
              timeRange={selectedTimeRange}
            />
          </div>

          <div className="severity-distribution">
            <div className="chart-header">
              <h3>Threat Severity Distribution</h3>
            </div>
            <div className="severity-chart">
              {threatTrends.severityDistribution?.map((item, index) => (
                <div key={index} className="severity-bar">
                  <div className="severity-label">
                    <span className="severity-name">{item.severity}</span>
                    <span className="severity-count">{item.count}</span>
                  </div>
                  <div className="severity-progress">
                    <div
                      className="severity-fill"
                      style={{
                        width: `${(item.count / Math.max(...threatTrends.severityDistribution.map(s => s.count))) * 100}%`,
                        backgroundColor: getSeverityColor(item.severity),
                      }}
                    ></div>
                  </div>
                </div>
              )) || []}
            </div>
          </div>
        </div>

        <div className="activity-section">
          <ActivityFeed
            activities={recentActivity}
            loading={loading.activity}
            onRefresh={() => dispatch(getRecentActivity(10))}
          />
        </div>
      </div>

      {/* Quick Actions */}
      <div className="quick-actions">
        <h3>Quick Actions</h3>
        <div className="action-buttons">
          <button className="action-btn primary">
            <span className="action-icon">🔍</span>
            <span>Start New Scan</span>
          </button>
          <button className="action-btn secondary">
            <span className="action-icon">📊</span>
            <span>Generate Report</span>
          </button>
          <button className="action-btn secondary">
            <span className="action-icon">⚙️</span>
            <span>Configure Settings</span>
          </button>
          <button className="action-btn secondary">
            <span className="action-icon">📥</span>
            <span>Export Data</span>
          </button>
        </div>
      </div>
    </div>
  );
};

const getSeverityColor = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return '#ef4444';
    case 'high':
      return '#f59e0b';
    case 'medium':
      return '#eab308';
    case 'low':
      return '#22c55e';
    default:
      return '#6b7280';
  }
};

export default Dashboard;
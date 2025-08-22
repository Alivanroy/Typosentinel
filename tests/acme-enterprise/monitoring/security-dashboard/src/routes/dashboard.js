const express = require('express');
const router = express.Router();
const { body, query, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const moment = require('moment');
const _ = require('lodash');

// Cache for dashboard data (5 minutes TTL)
const dashboardCache = new NodeCache({ stdTTL: 300 });

// Rate limiting for dashboard endpoints
const dashboardLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many dashboard requests, please try again later.',
});

router.use(dashboardLimiter);

/**
 * @swagger
 * /api/dashboard/overview:
 *   get:
 *     summary: Get dashboard overview
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: timeRange
 *         schema:
 *           type: string
 *           enum: [1h, 6h, 24h, 7d, 30d]
 *         description: Time range for metrics
 *     responses:
 *       200:
 *         description: Dashboard overview data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 summary:
 *                   type: object
 *                 vulnerabilities:
 *                   type: object
 *                 scans:
 *                   type: object
 *                 alerts:
 *                   type: object
 *                 registries:
 *                   type: object
 */
router.get('/overview', [
  query('timeRange').optional().isIn(['1h', '6h', '24h', '7d', '30d']),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const timeRange = req.query.timeRange || '24h';
    const cacheKey = `overview_${timeRange}_${req.user.id}`;
    
    // Check cache first
    const cachedData = dashboardCache.get(cacheKey);
    if (cachedData) {
      return res.json(cachedData);
    }

    const { postgres } = req.app.locals;
    const timeFilter = getTimeFilter(timeRange);

    // Get summary statistics
    const summaryQuery = `
      SELECT 
        COUNT(DISTINCT sr.id) as total_scans,
        COUNT(DISTINCT CASE WHEN sr.status = 'completed' THEN sr.id END) as completed_scans,
        COUNT(DISTINCT CASE WHEN sr.status = 'failed' THEN sr.id END) as failed_scans,
        COUNT(DISTINCT v.id) as total_vulnerabilities,
        COUNT(DISTINCT CASE WHEN v.severity = 'critical' THEN v.id END) as critical_vulnerabilities,
        COUNT(DISTINCT CASE WHEN v.severity = 'high' THEN v.id END) as high_vulnerabilities,
        COUNT(DISTINCT CASE WHEN v.severity = 'medium' THEN v.id END) as medium_vulnerabilities,
        COUNT(DISTINCT CASE WHEN v.severity = 'low' THEN v.id END) as low_vulnerabilities,
        COUNT(DISTINCT a.id) as total_alerts,
        COUNT(DISTINCT CASE WHEN a.status = 'active' THEN a.id END) as active_alerts,
        COUNT(DISTINCT r.id) as monitored_registries,
        AVG(sr.duration) as avg_scan_duration
      FROM scan_results sr
      LEFT JOIN vulnerabilities v ON sr.id = v.scan_result_id
      LEFT JOIN alerts a ON v.id = a.vulnerability_id
      LEFT JOIN registries r ON sr.registry_id = r.id
      WHERE sr.created_at >= $1
    `;

    const summaryResult = await postgres.query(summaryQuery, [timeFilter]);
    const summary = summaryResult.rows[0];

    // Get vulnerability trends
    const vulnerabilityTrendsQuery = `
      SELECT 
        DATE_TRUNC('hour', v.created_at) as time_bucket,
        v.severity,
        COUNT(*) as count
      FROM vulnerabilities v
      WHERE v.created_at >= $1
      GROUP BY time_bucket, v.severity
      ORDER BY time_bucket
    `;

    const vulnerabilityTrends = await postgres.query(vulnerabilityTrendsQuery, [timeFilter]);

    // Get scan performance metrics
    const scanMetricsQuery = `
      SELECT 
        r.name as registry_name,
        r.type as registry_type,
        COUNT(sr.id) as scan_count,
        AVG(sr.duration) as avg_duration,
        COUNT(CASE WHEN sr.status = 'completed' THEN 1 END) as success_count,
        COUNT(CASE WHEN sr.status = 'failed' THEN 1 END) as failure_count,
        MAX(sr.created_at) as last_scan
      FROM registries r
      LEFT JOIN scan_results sr ON r.id = sr.registry_id AND sr.created_at >= $1
      GROUP BY r.id, r.name, r.type
      ORDER BY scan_count DESC
    `;

    const scanMetrics = await postgres.query(scanMetricsQuery, [timeFilter]);

    // Get top vulnerabilities
    const topVulnerabilitiesQuery = `
      SELECT 
        v.package_name,
        v.package_version,
        v.vulnerability_id,
        v.severity,
        v.description,
        v.cvss_score,
        r.name as registry_name,
        COUNT(*) as occurrence_count
      FROM vulnerabilities v
      JOIN scan_results sr ON v.scan_result_id = sr.id
      JOIN registries r ON sr.registry_id = r.id
      WHERE v.created_at >= $1
      GROUP BY v.package_name, v.package_version, v.vulnerability_id, v.severity, v.description, v.cvss_score, r.name
      ORDER BY v.cvss_score DESC, occurrence_count DESC
      LIMIT 10
    `;

    const topVulnerabilities = await postgres.query(topVulnerabilitiesQuery, [timeFilter]);

    // Get recent alerts
    const recentAlertsQuery = `
      SELECT 
        a.id,
        a.type,
        a.severity,
        a.title,
        a.description,
        a.status,
        a.created_at,
        v.package_name,
        r.name as registry_name
      FROM alerts a
      LEFT JOIN vulnerabilities v ON a.vulnerability_id = v.id
      LEFT JOIN scan_results sr ON v.scan_result_id = sr.id
      LEFT JOIN registries r ON sr.registry_id = r.id
      WHERE a.created_at >= $1
      ORDER BY a.created_at DESC
      LIMIT 20
    `;

    const recentAlerts = await postgres.query(recentAlertsQuery, [timeFilter]);

    // Get compliance status
    const complianceQuery = `
      SELECT 
        policy_name,
        status,
        COUNT(*) as count
      FROM compliance_checks
      WHERE created_at >= $1
      GROUP BY policy_name, status
      ORDER BY policy_name
    `;

    const complianceStatus = await postgres.query(complianceQuery, [timeFilter]);

    // Get zero-day detection metrics
    const zerodayQuery = `
      SELECT 
        COUNT(*) as total_detections,
        COUNT(CASE WHEN confidence_score >= 0.8 THEN 1 END) as high_confidence,
        COUNT(CASE WHEN confidence_score >= 0.6 AND confidence_score < 0.8 THEN 1 END) as medium_confidence,
        COUNT(CASE WHEN confidence_score < 0.6 THEN 1 END) as low_confidence,
        AVG(confidence_score) as avg_confidence
      FROM zero_day_detections
      WHERE created_at >= $1
    `;

    const zeroday = await postgres.query(zerodayQuery, [timeFilter]);

    // Calculate risk score
    const riskScore = calculateRiskScore({
      criticalVulns: parseInt(summary.critical_vulnerabilities) || 0,
      highVulns: parseInt(summary.high_vulnerabilities) || 0,
      activeAlerts: parseInt(summary.active_alerts) || 0,
      failedScans: parseInt(summary.failed_scans) || 0,
      totalScans: parseInt(summary.total_scans) || 1,
    });

    // Prepare response data
    const dashboardData = {
      summary: {
        ...summary,
        risk_score: riskScore,
        scan_success_rate: summary.total_scans > 0 
          ? ((summary.completed_scans / summary.total_scans) * 100).toFixed(2)
          : 0,
        avg_scan_duration: summary.avg_scan_duration 
          ? parseFloat(summary.avg_scan_duration).toFixed(2)
          : 0,
      },
      vulnerabilities: {
        trends: processVulnerabilityTrends(vulnerabilityTrends.rows, timeRange),
        distribution: {
          critical: parseInt(summary.critical_vulnerabilities) || 0,
          high: parseInt(summary.high_vulnerabilities) || 0,
          medium: parseInt(summary.medium_vulnerabilities) || 0,
          low: parseInt(summary.low_vulnerabilities) || 0,
        },
        top: topVulnerabilities.rows,
      },
      scans: {
        metrics: scanMetrics.rows,
        performance: calculateScanPerformance(scanMetrics.rows),
      },
      alerts: {
        recent: recentAlerts.rows,
        summary: {
          total: parseInt(summary.total_alerts) || 0,
          active: parseInt(summary.active_alerts) || 0,
          resolved: (parseInt(summary.total_alerts) || 0) - (parseInt(summary.active_alerts) || 0),
        },
      },
      registries: {
        monitored: scanMetrics.rows.length,
        status: scanMetrics.rows.map(r => ({
          name: r.registry_name,
          type: r.registry_type,
          status: r.last_scan ? 'active' : 'inactive',
          last_scan: r.last_scan,
          success_rate: r.scan_count > 0 
            ? ((r.success_count / r.scan_count) * 100).toFixed(2)
            : 0,
        })),
      },
      compliance: {
        status: processComplianceStatus(complianceStatus.rows),
      },
      zeroday: {
        ...zeroday.rows[0],
        detection_rate: summary.total_scans > 0
          ? ((zeroday.rows[0]?.total_detections || 0) / summary.total_scans * 100).toFixed(2)
          : 0,
      },
      metadata: {
        time_range: timeRange,
        generated_at: new Date().toISOString(),
        cache_ttl: 300,
      },
    };

    // Cache the result
    dashboardCache.set(cacheKey, dashboardData);

    res.json(dashboardData);
  } catch (error) {
    console.error('Dashboard overview error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @swagger
 * /api/dashboard/metrics:
 *   get:
 *     summary: Get real-time metrics
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Real-time metrics data
 */
router.get('/metrics', async (req, res) => {
  try {
    const { redis } = req.app.locals;
    
    // Get real-time metrics from Redis
    const metrics = await redis.hgetall('typosentinel:metrics:realtime');
    
    // Get system metrics
    const systemMetrics = {
      cpu_usage: await redis.get('system:cpu_usage') || 0,
      memory_usage: await redis.get('system:memory_usage') || 0,
      disk_usage: await redis.get('system:disk_usage') || 0,
      network_io: await redis.get('system:network_io') || 0,
    };
    
    // Get active scans
    const activeScans = await redis.smembers('typosentinel:scans:active');
    
    // Get queue status
    const queueStatus = {
      pending: await redis.llen('typosentinel:queue:pending') || 0,
      processing: await redis.llen('typosentinel:queue:processing') || 0,
      failed: await redis.llen('typosentinel:queue:failed') || 0,
    };
    
    res.json({
      typosentinel: metrics,
      system: systemMetrics,
      scans: {
        active: activeScans.length,
        active_list: activeScans,
      },
      queue: queueStatus,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Metrics error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * @swagger
 * /api/dashboard/health:
 *   get:
 *     summary: Get system health status
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: System health status
 */
router.get('/health', async (req, res) => {
  try {
    const { postgres, redis } = req.app.locals;
    
    const health = {
      status: 'healthy',
      services: {},
      timestamp: new Date().toISOString(),
    };
    
    // Check PostgreSQL
    try {
      await postgres.query('SELECT 1');
      health.services.postgres = { status: 'healthy', response_time: 0 };
    } catch (error) {
      health.services.postgres = { status: 'unhealthy', error: error.message };
      health.status = 'degraded';
    }
    
    // Check Redis
    try {
      const start = Date.now();
      await redis.ping();
      health.services.redis = { 
        status: 'healthy', 
        response_time: Date.now() - start 
      };
    } catch (error) {
      health.services.redis = { status: 'unhealthy', error: error.message };
      health.status = 'degraded';
    }
    
    // Check Typosentinel API
    try {
      const axios = require('axios');
      const start = Date.now();
      await axios.get(`${process.env.TYPOSENTINEL_API_URL}/health`, {
        timeout: 5000,
        headers: {
          'Authorization': `Bearer ${process.env.TYPOSENTINEL_API_KEY}`,
        },
      });
      health.services.typosentinel = { 
        status: 'healthy', 
        response_time: Date.now() - start 
      };
    } catch (error) {
      health.services.typosentinel = { status: 'unhealthy', error: error.message };
      health.status = 'degraded';
    }
    
    res.json(health);
  } catch (error) {
    console.error('Health check error:', error);
    res.status(500).json({ 
      status: 'unhealthy', 
      error: 'Internal server error',
      timestamp: new Date().toISOString(),
    });
  }
});

// Helper functions
function getTimeFilter(timeRange) {
  const now = new Date();
  switch (timeRange) {
    case '1h':
      return new Date(now.getTime() - 60 * 60 * 1000);
    case '6h':
      return new Date(now.getTime() - 6 * 60 * 60 * 1000);
    case '24h':
      return new Date(now.getTime() - 24 * 60 * 60 * 1000);
    case '7d':
      return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    case '30d':
      return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    default:
      return new Date(now.getTime() - 24 * 60 * 60 * 1000);
  }
}

function calculateRiskScore(data) {
  const weights = {
    critical: 10,
    high: 5,
    activeAlerts: 3,
    failureRate: 2,
  };
  
  const failureRate = data.totalScans > 0 ? data.failedScans / data.totalScans : 0;
  
  const score = (
    data.criticalVulns * weights.critical +
    data.highVulns * weights.high +
    data.activeAlerts * weights.activeAlerts +
    failureRate * 100 * weights.failureRate
  );
  
  return Math.min(Math.round(score), 100);
}

function processVulnerabilityTrends(trends, timeRange) {
  const buckets = generateTimeBuckets(timeRange);
  const severities = ['critical', 'high', 'medium', 'low'];
  
  const processedTrends = buckets.map(bucket => {
    const bucketData = { time: bucket };
    severities.forEach(severity => {
      const trend = trends.find(t => 
        moment(t.time_bucket).isSame(bucket, 'hour') && t.severity === severity
      );
      bucketData[severity] = trend ? parseInt(trend.count) : 0;
    });
    return bucketData;
  });
  
  return processedTrends;
}

function generateTimeBuckets(timeRange) {
  const buckets = [];
  const now = moment();
  let interval, count;
  
  switch (timeRange) {
    case '1h':
      interval = 'minutes';
      count = 60;
      break;
    case '6h':
      interval = 'minutes';
      count = 360;
      break;
    case '24h':
      interval = 'hours';
      count = 24;
      break;
    case '7d':
      interval = 'hours';
      count = 168;
      break;
    case '30d':
      interval = 'days';
      count = 30;
      break;
    default:
      interval = 'hours';
      count = 24;
  }
  
  for (let i = count - 1; i >= 0; i--) {
    buckets.push(moment(now).subtract(i, interval).toDate());
  }
  
  return buckets;
}

function calculateScanPerformance(scanMetrics) {
  if (!scanMetrics.length) {
    return {
      avg_duration: 0,
      success_rate: 0,
      throughput: 0,
    };
  }
  
  const totalScans = scanMetrics.reduce((sum, m) => sum + parseInt(m.scan_count), 0);
  const totalSuccess = scanMetrics.reduce((sum, m) => sum + parseInt(m.success_count), 0);
  const avgDuration = scanMetrics.reduce((sum, m) => sum + parseFloat(m.avg_duration || 0), 0) / scanMetrics.length;
  
  return {
    avg_duration: avgDuration.toFixed(2),
    success_rate: totalScans > 0 ? ((totalSuccess / totalScans) * 100).toFixed(2) : 0,
    throughput: totalScans,
  };
}

function processComplianceStatus(complianceData) {
  const policies = _.groupBy(complianceData, 'policy_name');
  
  return Object.keys(policies).map(policyName => {
    const policyData = policies[policyName];
    const total = policyData.reduce((sum, p) => sum + parseInt(p.count), 0);
    const passed = policyData.find(p => p.status === 'passed')?.count || 0;
    const failed = policyData.find(p => p.status === 'failed')?.count || 0;
    
    return {
      policy: policyName,
      total,
      passed: parseInt(passed),
      failed: parseInt(failed),
      compliance_rate: total > 0 ? ((passed / total) * 100).toFixed(2) : 0,
    };
  });
}

module.exports = router;
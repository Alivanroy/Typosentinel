const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const Redis = require('ioredis');
const { Server } = require('socket.io');
const http = require('http');
const path = require('path');
const fs = require('fs');
const cron = require('node-cron');
const promClient = require('prom-client');
const { Client } = require('@elastic/elasticsearch');
const { Pool } = require('pg');
require('dotenv').config();

// Import route modules
const dashboardRoutes = require('./src/routes/dashboard');
const alertsRoutes = require('./src/routes/alerts');
const metricsRoutes = require('./src/routes/metrics');
const reportsRoutes = require('./src/routes/reports');
const vulnerabilitiesRoutes = require('./src/routes/vulnerabilities');
const registriesRoutes = require('./src/routes/registries');
const complianceRoutes = require('./src/routes/compliance');
const authRoutes = require('./src/routes/auth');
const adminRoutes = require('./src/routes/admin');
const apiRoutes = require('./src/routes/api');

// Import middleware
const authMiddleware = require('./src/middleware/auth');
const errorHandler = require('./src/middleware/errorHandler');
const requestLogger = require('./src/middleware/requestLogger');
const securityMiddleware = require('./src/middleware/security');

// Import services
const MetricsCollector = require('./src/services/metricsCollector');
const AlertManager = require('./src/services/alertManager');
const ReportGenerator = require('./src/services/reportGenerator');
const VulnerabilityScanner = require('./src/services/vulnerabilityScanner');
const ComplianceChecker = require('./src/services/complianceChecker');
const NotificationService = require('./src/services/notificationService');
const CacheService = require('./src/services/cacheService');
const DatabaseService = require('./src/services/databaseService');
const ElasticsearchService = require('./src/services/elasticsearchService');
const SocketService = require('./src/services/socketService');

// Configuration
const config = {
  port: process.env.PORT || 4000,
  nodeEnv: process.env.NODE_ENV || 'development',
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD,
    db: process.env.REDIS_DB || 0,
  },
  postgres: {
    host: process.env.POSTGRES_HOST || 'localhost',
    port: process.env.POSTGRES_PORT || 5432,
    database: process.env.POSTGRES_DB || 'typosentinel',
    user: process.env.POSTGRES_USER || 'postgres',
    password: process.env.POSTGRES_PASSWORD,
  },
  elasticsearch: {
    node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
    auth: {
      username: process.env.ELASTICSEARCH_USER || 'elastic',
      password: process.env.ELASTICSEARCH_PASSWORD,
    },
  },
  typosentinel: {
    apiUrl: process.env.TYPOSENTINEL_API_URL || 'http://localhost:8080',
    apiKey: process.env.TYPOSENTINEL_API_KEY,
    webhookSecret: process.env.TYPOSENTINEL_WEBHOOK_SECRET,
  },
  security: {
    jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key',
    sessionSecret: process.env.SESSION_SECRET || 'your-super-secret-session-key',
    encryptionKey: process.env.ENCRYPTION_KEY,
  },
  monitoring: {
    prometheusEnabled: process.env.PROMETHEUS_ENABLED === 'true',
    jaegerEnabled: process.env.JAEGER_ENABLED === 'true',
    elasticsearchEnabled: process.env.ELASTICSEARCH_ENABLED === 'true',
  },
  notifications: {
    slack: {
      webhookUrl: process.env.SLACK_WEBHOOK_URL,
      channel: process.env.SLACK_CHANNEL || '#security-alerts',
    },
    email: {
      smtp: {
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD,
        },
      },
      from: process.env.EMAIL_FROM || 'security@acme.com',
      to: process.env.EMAIL_TO || 'security-team@acme.com',
    },
    pagerduty: {
      integrationKey: process.env.PAGERDUTY_INTEGRATION_KEY,
    },
    teams: {
      webhookUrl: process.env.TEAMS_WEBHOOK_URL,
    },
  },
};

// Logger configuration
const logger = winston.createLogger({
  level: config.nodeEnv === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'acme-security-dashboard' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

// Prometheus metrics
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// Custom metrics
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.5, 1, 2, 5],
});

const httpRequestTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
});

const vulnerabilitiesTotal = new promClient.Gauge({
  name: 'typosentinel_vulnerabilities_total',
  help: 'Total number of vulnerabilities detected',
  labelNames: ['severity', 'registry', 'package'],
});

const scanDuration = new promClient.Histogram({
  name: 'typosentinel_scan_duration_seconds',
  help: 'Duration of Typosentinel scans in seconds',
  labelNames: ['registry', 'scan_type'],
  buckets: [1, 5, 10, 30, 60, 300],
});

const alertsTotal = new promClient.Counter({
  name: 'security_alerts_total',
  help: 'Total number of security alerts',
  labelNames: ['type', 'severity', 'source'],
});

register.registerMetric(httpRequestDuration);
register.registerMetric(httpRequestTotal);
register.registerMetric(vulnerabilitiesTotal);
register.registerMetric(scanDuration);
register.registerMetric(alertsTotal);

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST'],
  },
});

// Initialize services
let redis, postgres, elasticsearch;
let metricsCollector, alertManager, reportGenerator;
let vulnerabilityScanner, complianceChecker, notificationService;
let cacheService, databaseService, elasticsearchService, socketService;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'ws:', 'wss:'],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

// CORS
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true,
}));

// Compression
app.use(compression());

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.info(message.trim()),
  },
}));

// Custom request logger middleware
app.use(requestLogger);

// Metrics middleware
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    const route = req.route ? req.route.path : req.path;
    
    httpRequestDuration
      .labels(req.method, route, res.statusCode.toString())
      .observe(duration);
    
    httpRequestTotal
      .labels(req.method, route, res.statusCode.toString())
      .inc();
  });
  
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  const healthCheck = {
    uptime: process.uptime(),
    message: 'OK',
    timestamp: new Date().toISOString(),
    services: {
      redis: redis ? 'connected' : 'disconnected',
      postgres: postgres ? 'connected' : 'disconnected',
      elasticsearch: elasticsearch ? 'connected' : 'disconnected',
    },
  };
  
  res.status(200).json(healthCheck);
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (error) {
    res.status(500).end(error.message);
  }
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', authMiddleware, dashboardRoutes);
app.use('/api/alerts', authMiddleware, alertsRoutes);
app.use('/api/metrics', authMiddleware, metricsRoutes);
app.use('/api/reports', authMiddleware, reportsRoutes);
app.use('/api/vulnerabilities', authMiddleware, vulnerabilitiesRoutes);
app.use('/api/registries', authMiddleware, registriesRoutes);
app.use('/api/compliance', authMiddleware, complianceRoutes);
app.use('/api/admin', authMiddleware, adminRoutes);
app.use('/api', authMiddleware, apiRoutes);

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Serve React app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use(errorHandler);

// Initialize services
async function initializeServices() {
  try {
    // Initialize Redis
    redis = new Redis(config.redis);
    redis.on('connect', () => logger.info('Connected to Redis'));
    redis.on('error', (err) => logger.error('Redis connection error:', err));
    
    // Initialize PostgreSQL
    postgres = new Pool(config.postgres);
    await postgres.query('SELECT NOW()');
    logger.info('Connected to PostgreSQL');
    
    // Initialize Elasticsearch
    if (config.monitoring.elasticsearchEnabled) {
      elasticsearch = new Client(config.elasticsearch);
      await elasticsearch.ping();
      logger.info('Connected to Elasticsearch');
    }
    
    // Initialize services
    cacheService = new CacheService(redis);
    databaseService = new DatabaseService(postgres);
    elasticsearchService = new ElasticsearchService(elasticsearch);
    socketService = new SocketService(io);
    
    metricsCollector = new MetricsCollector({
      redis,
      postgres,
      elasticsearch,
      typosentinelApi: config.typosentinel.apiUrl,
      prometheusRegistry: register,
    });
    
    alertManager = new AlertManager({
      redis,
      postgres,
      notificationConfig: config.notifications,
      socketService,
    });
    
    reportGenerator = new ReportGenerator({
      postgres,
      elasticsearch,
      cacheService,
    });
    
    vulnerabilityScanner = new VulnerabilityScanner({
      typosentinelApi: config.typosentinel.apiUrl,
      apiKey: config.typosentinel.apiKey,
      postgres,
      redis,
    });
    
    complianceChecker = new ComplianceChecker({
      postgres,
      elasticsearch,
      alertManager,
    });
    
    notificationService = new NotificationService(config.notifications);
    
    // Start background tasks
    startBackgroundTasks();
    
    logger.info('All services initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize services:', error);
    process.exit(1);
  }
}

// Background tasks
function startBackgroundTasks() {
  // Collect metrics every minute
  cron.schedule('* * * * *', async () => {
    try {
      await metricsCollector.collectMetrics();
    } catch (error) {
      logger.error('Error collecting metrics:', error);
    }
  });
  
  // Check for alerts every 30 seconds
  cron.schedule('*/30 * * * * *', async () => {
    try {
      await alertManager.checkAlerts();
    } catch (error) {
      logger.error('Error checking alerts:', error);
    }
  });
  
  // Generate daily reports at 6 AM
  cron.schedule('0 6 * * *', async () => {
    try {
      await reportGenerator.generateDailyReport();
    } catch (error) {
      logger.error('Error generating daily report:', error);
    }
  });
  
  // Run vulnerability scans every hour
  cron.schedule('0 * * * *', async () => {
    try {
      await vulnerabilityScanner.runScheduledScan();
    } catch (error) {
      logger.error('Error running vulnerability scan:', error);
    }
  });
  
  // Check compliance every 4 hours
  cron.schedule('0 */4 * * *', async () => {
    try {
      await complianceChecker.runComplianceCheck();
    } catch (error) {
      logger.error('Error running compliance check:', error);
    }
  });
  
  // Clean up old data daily at 2 AM
  cron.schedule('0 2 * * *', async () => {
    try {
      await cleanupOldData();
    } catch (error) {
      logger.error('Error cleaning up old data:', error);
    }
  });
}

// Cleanup function
async function cleanupOldData() {
  const retentionDays = 90;
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
  
  try {
    // Clean up old scan results
    await postgres.query(
      'DELETE FROM scan_results WHERE created_at < $1',
      [cutoffDate]
    );
    
    // Clean up old alerts
    await postgres.query(
      'DELETE FROM alerts WHERE created_at < $1 AND status = $2',
      [cutoffDate, 'resolved']
    );
    
    // Clean up old metrics
    await postgres.query(
      'DELETE FROM metrics WHERE timestamp < $1',
      [cutoffDate]
    );
    
    logger.info(`Cleaned up data older than ${retentionDays} days`);
  } catch (error) {
    logger.error('Error during cleanup:', error);
  }
}

// Socket.IO connection handling
io.on('connection', (socket) => {
  logger.info(`Client connected: ${socket.id}`);
  
  socket.on('subscribe', (room) => {
    socket.join(room);
    logger.info(`Client ${socket.id} subscribed to ${room}`);
  });
  
  socket.on('unsubscribe', (room) => {
    socket.leave(room);
    logger.info(`Client ${socket.id} unsubscribed from ${room}`);
  });
  
  socket.on('disconnect', () => {
    logger.info(`Client disconnected: ${socket.id}`);
  });
});

// Graceful shutdown
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown(signal) {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);
  
  // Stop accepting new connections
  server.close(() => {
    logger.info('HTTP server closed');
  });
  
  // Close database connections
  try {
    if (redis) {
      await redis.quit();
      logger.info('Redis connection closed');
    }
    
    if (postgres) {
      await postgres.end();
      logger.info('PostgreSQL connection closed');
    }
    
    if (elasticsearch) {
      await elasticsearch.close();
      logger.info('Elasticsearch connection closed');
    }
  } catch (error) {
    logger.error('Error during shutdown:', error);
  }
  
  process.exit(0);
}

// Start server
async function startServer() {
  try {
    // Create logs directory if it doesn't exist
    if (!fs.existsSync('logs')) {
      fs.mkdirSync('logs');
    }
    
    // Initialize services
    await initializeServices();
    
    // Start server
    server.listen(config.port, () => {
      logger.info(`ACME Security Dashboard running on port ${config.port}`);
      logger.info(`Environment: ${config.nodeEnv}`);
      logger.info(`Dashboard URL: http://localhost:${config.port}`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Export for testing
module.exports = { app, server, io, config, logger };

// Start server if this file is run directly
if (require.main === module) {
  startServer();
}
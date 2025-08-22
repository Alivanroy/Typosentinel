const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'acme-backend-api' },
  transports: [
    new winston.transports.File({ filename: './logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: './logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth requests per windowMs
  message: 'Too many authentication attempts, please try again later.'
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(limiter);

// In-memory storage (for demo purposes - vulnerable by design)
let users = [
  {
    id: '1',
    username: 'admin',
    email: 'admin@acme.local',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'admin',
    apiKey: 'acme-admin-key-12345'
  },
  {
    id: '2',
    username: 'user',
    email: 'user@acme.local',
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'user',
    apiKey: 'acme-user-key-67890'
  }
];

let packages = [
  {
    id: '1',
    name: 'lodash',
    version: '4.17.21',
    registry: 'npm',
    description: 'A modern JavaScript utility library delivering modularity, performance, & extras.',
    vulnerabilities: [],
    riskScore: 0.1
  },
  {
    id: '2',
    name: 'express',
    version: '4.18.2',
    registry: 'npm',
    description: 'Fast, unopinionated, minimalist web framework for node.',
    vulnerabilities: [],
    riskScore: 0.2
  },
  {
    id: '3',
    name: 'lodash-utils', // Potential typosquatting target
    version: '1.0.0',
    registry: 'npm',
    description: 'Utility functions for lodash (SUSPICIOUS PACKAGE)',
    vulnerabilities: ['CVE-2023-FAKE-001'],
    riskScore: 0.9
  }
];

// JWT Secret (vulnerable - hardcoded)
const JWT_SECRET = process.env.JWT_SECRET || 'acme-super-secret-key-2023';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// API Key authentication (vulnerable implementation)
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  // Vulnerable: Direct comparison without proper validation
  const user = users.find(u => u.apiKey === apiKey);
  if (!user) {
    return res.status(403).json({ error: 'Invalid API key' });
  }

  req.user = user;
  next();
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// Authentication endpoints
app.post('/auth/login', authLimiter, [
  body('username').notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    
    // Vulnerable: SQL injection simulation (if using real DB)
    // const query = `SELECT * FROM users WHERE username = '${username}'`;
    
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    logger.info(`User ${username} logged in successfully`);
    
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User registration (vulnerable)
app.post('/auth/register', [
  body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = users.find(u => u.username === username || u.email === email);
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    const newUser = {
      id: uuidv4(),
      username,
      email,
      password: hashedPassword,
      role: 'user',
      apiKey: `acme-${username}-${crypto.randomBytes(8).toString('hex')}`
    };

    users.push(newUser);
    
    logger.info(`New user registered: ${username}`);
    
    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Package scanning endpoints
app.get('/packages', authenticateToken, (req, res) => {
  try {
    const { registry, search, limit = 10, offset = 0 } = req.query;
    
    let filteredPackages = packages;
    
    if (registry) {
      filteredPackages = filteredPackages.filter(p => p.registry === registry);
    }
    
    if (search) {
      filteredPackages = filteredPackages.filter(p => 
        p.name.toLowerCase().includes(search.toLowerCase()) ||
        p.description.toLowerCase().includes(search.toLowerCase())
      );
    }
    
    const paginatedPackages = filteredPackages.slice(offset, offset + parseInt(limit));
    
    res.json({
      packages: paginatedPackages,
      total: filteredPackages.length,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (error) {
    logger.error('Package listing error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/packages/:id', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    const package = packages.find(p => p.id === id);
    
    if (!package) {
      return res.status(404).json({ error: 'Package not found' });
    }
    
    res.json(package);
  } catch (error) {
    logger.error('Package retrieval error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Vulnerable endpoint - Direct package scanning without proper validation
app.post('/scan/package', authenticateApiKey, (req, res) => {
  try {
    const { name, version, registry } = req.body;
    
    // Vulnerable: No input validation
    if (!name) {
      return res.status(400).json({ error: 'Package name is required' });
    }
    
    // Simulate package scanning
    const scanResult = {
      id: uuidv4(),
      package: { name, version: version || 'latest', registry: registry || 'npm' },
      scanTimestamp: new Date().toISOString(),
      threats: [],
      riskScore: Math.random(),
      status: 'completed'
    };
    
    // Simulate threat detection for suspicious packages
    if (name.includes('lodash-utils') || name.includes('express-utils')) {
      scanResult.threats.push({
        type: 'typosquatting',
        severity: 'high',
        description: 'Potential typosquatting attack detected',
        confidence: 0.9
      });
      scanResult.riskScore = 0.95;
    }
    
    logger.info(`Package scan completed for ${name}@${version || 'latest'}`);
    
    res.json(scanResult);
  } catch (error) {
    logger.error('Package scan error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Vulnerable file upload endpoint
app.post('/upload/package', authenticateToken, (req, res) => {
  try {
    // Vulnerable: No file type validation, size limits, or security checks
    const { filename, content } = req.body;
    
    if (!filename || !content) {
      return res.status(400).json({ error: 'Filename and content are required' });
    }
    
    // Simulate file processing (vulnerable to various attacks)
    const uploadResult = {
      id: uuidv4(),
      filename,
      size: content.length,
      uploadTimestamp: new Date().toISOString(),
      status: 'processed'
    };
    
    logger.info(`File uploaded: ${filename}`);
    
    res.json(uploadResult);
  } catch (error) {
    logger.error('File upload error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin endpoints (vulnerable authorization)
app.get('/admin/users', authenticateToken, (req, res) => {
  try {
    // Vulnerable: No proper role-based access control
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    // Vulnerable: Exposing sensitive user data
    res.json(users);
  } catch (error) {
    logger.error('Admin users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Vulnerable debug endpoint (should not exist in production)
app.get('/debug/env', (req, res) => {
  // Extremely vulnerable: Exposing environment variables
  res.json({
    environment: process.env,
    nodeVersion: process.version,
    platform: process.platform,
    memory: process.memoryUsage()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`ACME Backend API server running on port ${PORT}`);
  logger.info('Environment:', process.env.NODE_ENV || 'development');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

module.exports = app;
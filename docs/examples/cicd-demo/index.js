const express = require('express');
const _ = require('lodash');
const axios = require('axios');
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Sample route
app.get('/', (req, res) => {
  const response = {
    message: 'TypoSentinel CI/CD Demo Application',
    timestamp: moment().format(),
    id: uuidv4(),
    dependencies: {
      express: 'Web framework',
      lodash: 'Utility library',
      axios: 'HTTP client',
      moment: 'Date manipulation',
      uuid: 'UUID generation'
    }
  };
  
  res.json(response);
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: moment().format(),
    uptime: process.uptime()
  });
});

// API endpoint that uses dependencies
app.get('/api/data', async (req, res) => {
  try {
    // Use lodash to manipulate data
    const sampleData = _.range(1, 11).map(i => ({
      id: uuidv4(),
      value: i * 2,
      created: moment().subtract(i, 'days').format()
    }));
    
    res.json({
      data: sampleData,
      total: sampleData.length,
      generated: moment().format()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Demo app running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔍 This app will be scanned by TypoSentinel in CI/CD`);
});
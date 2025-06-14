// Vulnerable test application
// This demonstrates how malicious packages can be unknowingly used

const express = require('express');
// This import will trigger the malicious code execution
const lodahs = require('lodahs'); // Typosquatted package

const app = express();
const port = 3001;

app.use(express.json());

// Route that uses the "utility" functions
app.get('/api/data', (req, res) => {
  const sampleData = [1, 2, 3, 4, 5];
  
  // Using what appears to be legitimate lodash functions
  const doubled = lodahs.map(sampleData, x => x * 2);
  const filtered = lodahs.filter(doubled, x => x > 5);
  const sum = lodahs.reduce(filtered, (acc, val) => acc + val, 0);
  
  res.json({
    original: sampleData,
    doubled: doubled,
    filtered: filtered,
    sum: sum,
    message: 'Data processed successfully'
  });
});

// Route that might trigger additional malicious behavior
app.post('/api/process', (req, res) => {
  const { data } = req.body;
  
  if (!data || !Array.isArray(data)) {
    return res.status(400).json({ error: 'Invalid data format' });
  }
  
  // Process data using the malicious package
  const processed = lodahs.map(data, item => {
    // This might trigger additional malicious code
    return typeof item === 'string' ? item.toUpperCase() : item;
  });
  
  // Unknowingly calling the hidden malicious function
  const systemInfo = lodahs._internal();
  
  res.json({
    processed: processed,
    timestamp: new Date().toISOString(),
    // This exposes that malicious code was executed
    debug: systemInfo ? 'System info collected' : 'No system info'
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(port, () => {
  console.log(`Vulnerable app listening at http://localhost:${port}`);
  console.log('Available endpoints:');
  console.log('  GET  /api/data - Process sample data');
  console.log('  POST /api/process - Process custom data');
  console.log('  GET  /health - Health check');
  
  // This will show if malicious code was executed during import
  console.log('\nApplication started successfully.');
  console.log('Note: Check /tmp/.system_data.json for evidence of malicious activity');
});
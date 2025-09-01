const express = require('express');
const app = express();
const port = process.env.PORT || 3004;

app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', service: 'payment' });
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({ message: 'Payment Service', version: '1.0.0' });
});

// Basic payment endpoints
app.post('/process', (req, res) => {
  res.status(200).json({ message: 'Payment processed successfully', transactionId: 'txn_123' });
});

app.get('/transaction/:id', (req, res) => {
  res.status(200).json({ id: req.params.id, status: 'completed', amount: 100 });
});

app.listen(port, () => {
  console.log(`Payment service listening on port ${port}`);
});
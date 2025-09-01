const express = require('express');
const app = express();
const port = process.env.PORT || 3003;

app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', service: 'notification' });
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({ message: 'Notification Service', version: '1.0.0' });
});

// Basic notification endpoints
app.post('/send', (req, res) => {
  res.status(200).json({ message: 'Notification sent successfully' });
});

app.get('/status/:id', (req, res) => {
  res.status(200).json({ id: req.params.id, status: 'delivered' });
});

app.listen(port, () => {
  console.log(`Notification service listening on port ${port}`);
});
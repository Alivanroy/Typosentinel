const express = require('express');
const app = express();
const port = process.env.PORT || 3005;

app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', service: 'user' });
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({ message: 'User Service', version: '1.0.0' });
});

// Basic user endpoints
app.get('/users', (req, res) => {
  res.status(200).json({ users: [], total: 0 });
});

app.get('/users/:id', (req, res) => {
  res.status(200).json({ id: req.params.id, name: 'Sample User', email: 'user@example.com' });
});

app.post('/users', (req, res) => {
  res.status(201).json({ message: 'User created successfully', id: 'user_123' });
});

app.listen(port, () => {
  console.log(`User service listening on port ${port}`);
});
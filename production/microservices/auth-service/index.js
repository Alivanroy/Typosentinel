const express = require('express');
const app = express();
const port = process.env.PORT || 3001;

app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', service: 'auth' });
});

// Root endpoint
app.get('/', (req, res) => {
  res.status(200).json({ message: 'Auth Service', version: '1.0.0' });
});

// Basic auth endpoints
app.post('/login', (req, res) => {
  res.status(200).json({ message: 'Login endpoint', token: 'mock-token' });
});

app.post('/register', (req, res) => {
  res.status(201).json({ message: 'User registered successfully' });
});

app.listen(port, () => {
  console.log(`Auth service listening on port ${port}`);
});
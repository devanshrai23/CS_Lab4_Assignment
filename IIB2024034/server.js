const express = require('express');
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Initialize database with seed users
db.initDatabase();

// ----------------------------------------------------
// API ROUTES
// ----------------------------------------------------

/**
 * Route: Login Authentication
 * Demonstrates SQL Injection: Authentication Bypass (Vulnerable vs Mitigated)
 */
app.post('/api/login', (req, res) => {
  const { username = '', password = '', mode = 'vulnerable' } = req.body;

  let result;
  if (mode === 'mitigated') {
    result = db.loginMitigated(username, password);
  } else {
    result = db.loginVulnerable(username, password);
  }

  res.json(result);
});

/**
 * Route: Reset Database to initial state
 */
app.post('/api/reset-db', (req, res) => {
  try {
    db.initDatabase();
    res.json({ success: true, message: 'Database reset to clean seed state.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`Web Server Security Demo: SQL Injection (Auth Bypass)`);
  console.log(`Server running at: http://localhost:${PORT}`);
  console.log(`====================================================`);
});

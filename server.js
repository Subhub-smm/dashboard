
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'smm_panel'
});

db.connect((err) => {
  if (err) {
    console.error('DB connection failed:', err);
    return;
  }
  console.log('MySQL connected...');
});

// Root route for Render test
app.get('/', (req, res) => {
  res.send('✅ SMM Panel Backend is running');
});

// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.query('INSERT INTO users (username, password, balance) VALUES (?, ?, 0)', [username, hashedPassword], (err) => {
    if (err) return res.status(500).json({ message: 'User already exists or DB error' });
    res.status(201).json({ message: 'User registered successfully' });
  });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ message: 'User not found' });
    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET || 'secretKey');
    res.json({ token });
  });
});

// Place order
app.post('/order', (req, res) => {
  const { token, service, link, quantity } = req.body;
  const pricePerUnit = 0.05;
  const totalCost = quantity * pricePerUnit;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretKey');
    const userId = decoded.userId;

    db.query('SELECT balance FROM users WHERE id = ?', [userId], (err, results) => {
      if (err || results.length === 0) return res.status(500).json({ message: 'User not found' });
      const balance = results[0].balance;
      if (balance < totalCost) return res.status(400).json({ message: 'Insufficient balance' });

      db.query('INSERT INTO orders (user_id, service, link, quantity, status) VALUES (?, ?, ?, ?, ?)',
        [userId, service, link, quantity, 'Pending'], (err) => {
          if (err) return res.status(500).json({ message: 'Order failed' });

          db.query('UPDATE users SET balance = balance - ? WHERE id = ?', [totalCost, userId]);
          res.status(200).json({ message: 'Order placed successfully' });
        });
    });
  } catch (e) {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

// Order history
app.post('/order-history', (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretKey');
    const userId = decoded.userId;

    db.query('SELECT * FROM orders WHERE user_id = ?', [userId], (err, results) => {
      if (err) return res.status(500).json({ message: 'Could not retrieve orders' });
      res.status(200).json(results);
    });
  } catch (e) {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

// Admin top-up
app.post('/admin/topup', (req, res) => {
  const { username, amount, adminKey } = req.body;
  if (adminKey !== process.env.ADMIN_KEY) return res.status(403).json({ message: 'Forbidden' });

  db.query('UPDATE users SET balance = balance + ? WHERE username = ?', [amount, username], (err) => {
    if (err) return res.status(500).json({ message: 'Top-up failed' });
    res.status(200).json({ message: `Balance updated for ${username}` });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// Connect to Railway's database using its environment variable
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(express.json());
app.use(express.static(__dirname));

// Auto-create database tables on start if they don't exist
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password VARCHAR(100) NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INT REFERENCES users(id),
      receiver_id INT REFERENCES users(id),
      message_text TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}
initDb().catch(console.error);

// 1. SIGN UP
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );
    res.status(201).json({ message: "User created!", user: result.rows[0] });
  } catch (err) {
    res.status(400).json({ error: "Username already exists or invalid data" });
  }
});

// 2. LOGIN
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(400).json({ error: "User not found" });

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Incorrect password" });

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET || 'secret');
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// 3. SOCKET.IO REAL-TIME CHAT
io.on('connection', (socket) => {
  socket.on('join', (userId) => {
    socket.join(String(userId));
  });

  socket.on('private_message', async (data) => {
    const { senderId, receiverId, messageText } = data;
    try {
      await pool.query(
        'INSERT INTO messages (sender_id, receiver_id, message_text) VALUES ($1, $2, $3)',
        [senderId, receiverId, messageText]
      );
      io.to(String(receiverId)).emit('new_message', { senderId, messageText });
    } catch (err) {
      console.error(err);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Rate Limiting (Security)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', apiLimiter);

// MySQL Connection Pool Setup
const dbPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'secret',
  database: process.env.DB_NAME || 'vidichat_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_token_key_vidichat';

// --- AUTHENTICATION ENDPOINTS ---

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Please enter all fields.' });
  }

  try {
    const [existing] = await dbPool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'User with this email already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const userId = require('crypto').randomUUID();

    await dbPool.query(
      'INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)',
      [userId, name, email, passwordHash]
    );

    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: userId, name, email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Please enter all fields.' });
  }

  try {
    const [users] = await dbPool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'User does not exist.' });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Middleware for JWT Verification
const verifyToken = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) {
    return res.status(401).json({ error: 'No token, authorization denied.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ error: 'Token is not valid.' });
  }
};

// --- YOUTUBE ENDPOINTS ---

app.get('/api/videos', async (req, res) => {
  try {
    const [rows] = await dbPool.query(
      `SELECT v.*, u.name as creator_name, u.avatar_url as creator_avatar 
       FROM videos v 
       JOIN users u ON v.creator_id = u.id 
       ORDER BY v.created_at DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/videos', verifyToken, async (req, res) => {
  const { title, description, video_url, thumbnail_url, category } = req.body;
  if (!title || !video_url || !thumbnail_url) {
    return res.status(400).json({ error: 'Title, video url and thumbnail are required.' });
  }

  try {
    const videoId = require('crypto').randomUUID();
    await dbPool.query(
      `INSERT INTO videos (id, title, description, video_url, thumbnail_url, creator_id, category) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [videoId, title, description, video_url, thumbnail_url, req.user.id, category || 'All']
    );
    res.status(201).json({ id: videoId, title, description });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const [comments] = await dbPool.query(
      `SELECT c.*, u.name as user_name, u.avatar_url as user_avatar 
       FROM comments c 
       JOIN users u ON c.user_id = u.id 
       WHERE c.video_id = ? 
       ORDER BY c.created_at DESC`,
      [req.params.id]
    );
    res.json(comments);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/videos/:id/comments', verifyToken, async (req, res) => {
  const { content } = req.body;
  if (!content) {
    return res.status(400).json({ error: 'Comment body content is required.' });
  }

  try {
    const [result] = await dbPool.query(
      'INSERT INTO comments (video_id, user_id, content) VALUES (?, ?, ?)',
      [req.params.id, req.user.id, content]
    );
    res.status(201).json({ id: result.insertId, content });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- WHATSAPP ENDPOINTS ---

app.get('/api/chats', verifyToken, async (req, res) => {
  try {
    const [threads] = await dbPool.query(
      `SELECT t.*, 
       (SELECT m.message_text FROM chat_messages m WHERE m.thread_id = t.id ORDER BY m.created_at DESC LIMIT 1) as last_message,
       (SELECT m.created_at FROM chat_messages m WHERE m.thread_id = t.id ORDER BY m.created_at DESC LIMIT 1) as last_message_time
       FROM chat_threads t
       JOIN chat_participants p ON t.id = p.thread_id
       WHERE p.user_id = ?
       ORDER BY last_message_time DESC`,
      [req.user.id]
    );
    res.json(threads);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/chats/:id/messages', verifyToken, async (req, res) => {
  try {
    const [messages] = await dbPool.query(
      `SELECT m.*, u.name as sender_name 
       FROM chat_messages m
       JOIN users u ON m.sender_id = u.id
       WHERE m.thread_id = ?
       ORDER BY m.created_at ASC`,
      [req.params.id]
    );
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- SOCKET.IO CHAT AND CALLING ENGINE ---
const socketUsers = {}; // Map of userId -> socketId

io.on('connection', (socket) => {
  console.log('A client connected:', socket.id);

  // User online
  socket.on('join', async ({ userId }) => {
    socketUsers[userId] = socket.id;
    socket.userId = userId;
    console.log(`User ${userId} bound to socket ${socket.id}`);
  });

  // Private Messaging
  socket.on('send_message', async ({ threadId, senderId, text, mediaType, mediaUrl, durationSec }) => {
    try {
      // 1. Persist to MySQL
      const [res] = await dbPool.query(
        `INSERT INTO chat_messages (thread_id, sender_id, message_text, media_type, media_url, duration_sec) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [threadId, senderId, text, mediaType || 'TEXT', mediaUrl || null, durationSec || 0]
      );
      
      const messageId = res.insertId;

      // 2. Fetch thread participants
      const [participants] = await dbPool.query(
        'SELECT user_id FROM chat_participants WHERE thread_id = ?',
        [threadId]
      );

      // 3. Emit message back in real-time to active participants
      participants.forEach((part) => {
        const pSocket = socketUsers[part.user_id];
        if (pSocket) {
          io.to(pSocket).emit('receive_message', {
            id: messageId,
            threadId,
            senderId,
            messageText: text,
            mediaType: mediaType || 'TEXT',
            mediaUrl,
            durationSec
          });
        }
      });
    } catch (err) {
      console.error('Socket message error:', err);
    }
  });

  // Call Signaling (WebRTC wrapper for Voice/Video calling)
  socket.on('call_user', ({ userToCall, signalData, from, isVideo }) => {
    const targetSocket = socketUsers[userToCall];
    if (targetSocket) {
      io.to(targetSocket).emit('call_incoming', { signal: signalData, from, isVideo });
    }
  });

  socket.on('answer_call', ({ to, signal }) => {
    const targetSocket = socketUsers[to];
    if (targetSocket) {
      io.to(targetSocket).emit('call_accepted', signal);
    }
  });

  socket.on('disconnect', () => {
    if (socket.userId) {
      delete socketUsers[socket.userId];
      console.log(`User ${socket.userId} disconnected`);
    }
  });
});

// Start Server
const PORT = process.env.PORT || 5000;

async function initializeDatabase() {
  try {
    console.log('Connecting to database to verify tables...');
    
    // 1. Users Table
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(150) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        avatar_url VARCHAR(255) DEFAULT 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150',
        role VARCHAR(20) DEFAULT 'USER',
        is_online BOOLEAN DEFAULT FALSE,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_user_email (email),
        INDEX idx_user_role (role)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // 2. Videos Table
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS videos (
        id VARCHAR(36) PRIMARY KEY,
        title VARCHAR(150) NOT NULL,
        description TEXT,
        video_url VARCHAR(255) NOT NULL,
        thumbnail_url VARCHAR(255) NOT NULL,
        creator_id VARCHAR(36) NOT NULL,
        category VARCHAR(50) DEFAULT 'All',
        views BIGINT DEFAULT 0,
        likes BIGINT DEFAULT 0,
        dislikes BIGINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_video_creator (creator_id),
        INDEX idx_video_category (category),
        INDEX idx_video_views (views DESC)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // 3. Comments Table
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        video_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        content TEXT NOT NULL,
        likes BIGINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_comment_video (video_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // 4. Subscriptions Table
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        subscriber_id VARCHAR(36) NOT NULL,
        creator_id VARCHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (subscriber_id, creator_id),
        FOREIGN KEY (subscriber_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_subscription_subscriber (subscriber_id),
        INDEX idx_subscription_creator (creator_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // 5. Chat Threads Table
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS chat_threads (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(100) DEFAULT NULL,
        avatar_url VARCHAR(255) DEFAULT NULL,
        is_group BOOLEAN DEFAULT FALSE,
        created_by VARCHAR(36) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_thread_group (is_group)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // 6. Chat Participants Link Table
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS chat_participants (
        thread_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (thread_id, user_id),
        FOREIGN KEY (thread_id) REFERENCES chat_threads(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // 7. Chat Messages Table
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        thread_id VARCHAR(36) NOT NULL,
        sender_id VARCHAR(36) NOT NULL,
        message_text TEXT,
        media_type VARCHAR(20) DEFAULT 'TEXT',
        media_url VARCHAR(255) DEFAULT NULL,
        duration_sec INT DEFAULT 0,
        is_seen BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (thread_id) REFERENCES chat_threads(id) ON DELETE CASCADE,
        FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_message_thread (thread_id, created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // 8. Watch Later Links Table
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS watch_later (
        user_id VARCHAR(36) NOT NULL,
        video_id VARCHAR(36) NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, video_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // 9. Playlists Table
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS playlists (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        description TEXT,
        user_id VARCHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_playlist_user (user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // 10. Playlist Videos Table
    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS playlist_videos (
        playlist_id BIGINT NOT NULL,
        video_id VARCHAR(36) NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (playlist_id, video_id),
        FOREIGN KEY (playlist_id) REFERENCES playlists(id) ON DELETE CASCADE,
        FOREIGN KEY (video_id) REFERENCES videos(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    console.log('✅ Database schema verified and tables are initialized!');
  } catch (err) {
    console.error('❌ Database verification failed on startup:', err);
  }
}

server.listen(PORT, async () => {
  console.log(`VidChat backend server running smoothly on port ${PORT}`);
  await initializeDatabase();
});

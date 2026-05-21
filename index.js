You got it! If you just want a single, unified backend server file (index.js or server.js) that handles everything automatically—including setting up the new database columns so you don't have to manually execute any SQL—this code is exactly what you need.

When this script boots up, it automatically checks your PostgreSQL database and creates the is_banned and is_deleted columns if they don't already exist.

Here is your complete, self-initializing backend code:

JavaScript
import express from 'express'
import { WebSocketServer, WebSocket } from 'ws'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import pkg from 'pg'

const { Pool } = pkg 
const JWT_SECRET = process.env.JWT_SECRET || 'brutalist_secret_key_123'
const db = new Pool({ connectionString: process.env.DATABASE_URL })

// AUTOMATIC DATABASE MIGRATION ENGINE
// This runs on startup and handles all table creation and column updates automatically.
async function initDatabase() {
  // 1. Create base tables if they don't exist
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      timeout_until BIGINT DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      content TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS dms (
      id SERIAL PRIMARY KEY,
      sender TEXT NOT NULL,
      receiver TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      content TEXT NOT NULL
    );
  `);

  // 2. Automatically patch missing columns so you don't have to run SQL manually
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT false;`);
  await db.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT false;`);
  await db.query(`ALTER TABLE dms ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT false;`);

  console.log("PostgreSQL Connected. Tables and columns verified/updated automatically.");
}
initDatabase().catch(err => console.error("Database boot failure", err));

const app = express()
app.use(express.json())
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*")
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
  next()
})

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    next();
  } catch (err) { return res.status(403).json({ error: 'Invalid token' }); }
}

const activeClients = new Map()
function isMasterAdmin(name) { return name === 'augustinejames' || name === 'tockdev'; }

function broadcastOnlineRoster() {
  const payload = JSON.stringify({ type: 'roster_update', users: Array.from(activeClients.keys()) });
  activeClients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(payload); });
}

// REST ENDPOINTS
app.get('/dm-contacts', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT DISTINCT username FROM (
        SELECT receiver AS username FROM dms WHERE sender = $1
        UNION
        SELECT sender AS username FROM dms WHERE receiver = $1
      ) AS contacts WHERE username != $1;
    `, [req.user.username]);
    res.json(result.rows.map(row => row.username));
  } catch (err) { res.status(500).json({ error: 'Database fail' }); }
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await db.query('INSERT INTO users (username, password_hash) VALUES ($1, $2);', [username, hash]);
    res.json({ token: jwt.sign({ username }, JWT_SECRET), username });
  } catch (err) { res.status(400).json({ error: 'Registration rejected' }); }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1;', [username]);
    const user = result.rows[0];
    if (!user || user.is_banned || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Access denied / Suspended account profile' });
    }
    res.json({ token: jwt.sign({ username }, JWT_SECRET), username });
  } catch (err) { res.status(500).json({ error: 'Auth fail' }); }
});

app.get('/history', authenticateToken, async (req, res) => {
  const offset = parseInt(req.query.index ?? '0', 10) * 10;
  try {
    const result = await db.query('SELECT * FROM messages ORDER BY timestamp DESC LIMIT 10 OFFSET $1;', [offset]);
    res.json(result.rows.reverse()); 
  } catch (err) { res.status(500).json({ error: 'History read fail' }); }
});

app.get('/dm-history', authenticateToken, async (req, res) => {
  const offset = parseInt(req.query.index ?? '0', 10) * 10;
  try {
    const result = await db.query(`
      SELECT id, sender AS username, receiver, timestamp, content, is_deleted FROM dms 
      WHERE (sender = $1 AND receiver = $2) OR (sender = $2 AND receiver = $1)
      ORDER BY timestamp DESC LIMIT 10 OFFSET $3;
    `, [req.user.username, req.query.target, offset]);
    res.json(result.rows.reverse());
  } catch (err) { res.status(500).json({ error: 'DM history read fail' }); }
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => console.log(`Server handling ports across ${PORT}`));
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
  let authenticatedUser = null;

  function disconnectSocket(targetName) {
    const sock = activeClients.get(targetName);
    if (sock) {
      sock.send(JSON.stringify({ type: 'terminated' }));
      sock.close();
      activeClients.delete(targetName);
    }
  }

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);

      if (data.type === 'auth') {
        const decoded = jwt.verify(data.token, JWT_SECRET);
        authenticatedUser = decoded.username;

        const check = await db.query('SELECT is_banned, timeout_until FROM users WHERE username = $1;', [authenticatedUser]);
        if (check.rows[0] && (check.rows[0].is_banned || BigInt(check.rows[0].timeout_until) > BigInt(Date.now()))) {
          ws.send(JSON.stringify({ type: 'terminated' }));
          ws.close();
          return;
        }
        activeClients.set(authenticatedUser, ws);
        broadcastOnlineRoster();
        return;
      }

      if (!authenticatedUser) return;

      // CONTINUOUS COMPLIANCE INFRACTION MONITOR
      const statusCheck = await db.query('SELECT is_banned, timeout_until FROM users WHERE username = $1;', [authenticatedUser]);
      if (statusCheck.rows[0] && (statusCheck.rows[0].is_banned || BigInt(statusCheck.rows[0].timeout_until) > BigInt(Date.now()))) {
        ws.send(JSON.stringify({ type: 'terminated' }));
        ws.close();
        activeClients.delete(authenticatedUser);
        broadcastOnlineRoster();
        return;
      }

      // MODERATION LEVEL EXECUTORS
      if (isMasterAdmin(authenticatedUser)) {
        if (data.type === 'mod_timeout') {
          if (isMasterAdmin(data.target)) return;
          const until = Date.now() + (parseInt(data.duration, 10) * 60 * 1000);
          await db.query('UPDATE users SET timeout_until = $1 WHERE username = $2;', [until, data.target]);
          disconnectSocket(data.target);
          broadcastOnlineRoster();
          return;
        }

        if (data.type === 'mod_ban') {
          if (isMasterAdmin(data.target)) return;
          await db.query('UPDATE users SET is_banned = true WHERE username = $1;', [data.target]);
          disconnectSocket(data.target);
          broadcastOnlineRoster();
          return;
        }

        if (data.type === 'mod_pardon') {
          // UNDO INFRACTIONS: Reset ban fields and structural timeouts natively
          await db.query('UPDATE users SET is_banned = false, timeout_until = 0 WHERE username = $1;', [data.target]);
          return;
        }

        if (data.type === 'mod_restore') {
          // UNDO PURGE: Reverts a soft-deleted message record
          const targetTable = data.channel === 'public' ? 'messages' : 'dms';
          await db.query(`UPDATE ${targetTable} SET is_deleted = false WHERE id = $1;`, [data.id]);
          activeClients.forEach(c => { if(c.readyState === WebSocket.OPEN) c.send(JSON.stringify({ type: 'msg_restored', id: data.id })); });
          return;
        }
      }

      // MODERATOR OR SELF-SERVICE CONTENT SOFT-DELETION
      if (data.type === 'mod_delete') {
        const targetTable = data.channel === 'public' ? 'messages' : 'dms';
        
        // Ownership verification lookup
        const ownership = await db.query(`SELECT username, sender FROM ${targetTable} WHERE id = $1;`, [data.id]);
        if (!ownership.rows[0]) return;
        const recordOwner = ownership.rows[0].username || ownership.rows[0].sender;

        // Execute if performing self-delete OR if structural moderator is executing
        if (recordOwner === authenticatedUser || isMasterAdmin(authenticatedUser)) {
          await db.query(`UPDATE ${targetTable} SET is_deleted = true WHERE id = $1;`, [data.id]);
          const payload = JSON.stringify({ type: 'msg_deleted', id: data.id });
          activeClients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(payload); });
        }
        return;
      }

      if (data.type === 'message') {
        const timestamp = Date.now();
        const dbRes = await db.query('INSERT INTO messages (username, timestamp, content) VALUES ($1, $2, $3) RETURNING id;', [authenticatedUser, timestamp, data.content]);
        const broadcastPayload = JSON.stringify({
          type: 'message', id: dbRes.rows[0].id, username: authenticatedUser, timestamp, content: data.content, is_deleted: false
        });
        activeClients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(broadcastPayload); });
      }

      if (data.type === 'dm') {
        const timestamp = Date.now();
        const dbRes = await db.query('INSERT INTO dms (sender, receiver, timestamp, content) VALUES ($1, $2, $3, $4) RETURNING id;', [authenticatedUser, data.target, timestamp, data.content]);
        const dmPayload = JSON.stringify({
          type: 'dm', id: dbRes.rows[0].id, username: authenticatedUser, sender: authenticatedUser, receiver: data.target, timestamp, content: data.content, is_deleted: false
        });
        const recipientSocket = activeClients.get(data.target);
        if (recipientSocket && recipientSocket.readyState === WebSocket.OPEN) recipientSocket.send(dmPayload);
        ws.send(dmPayload);
      }

    } catch (err) { console.error("Error evaluating packet framework:", err); }
  });

  ws.on('close', () => {
    if (authenticatedUser) {
      activeClients.delete(authenticatedUser);
      broadcastOnlineRoster();
    }
  });
});

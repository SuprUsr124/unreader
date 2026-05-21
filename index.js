import express from 'express'
import { WebSocketServer, WebSocket } from 'ws'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import pkg from 'pg'
const { Client } = pkg

const JWT_SECRET = process.env.JWT_SECRET || 'brutalist_secret_key_123'

const db = new Client({
    connectionString: process.env.DATABASE_URL
})

async function initDatabase() {
    await db.connect();
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
    console.log("PostgreSQL Connected and Tables Ready");
}
initDatabase().catch(err => console.error("Database boot failure", err));

const app = express()
app.use(express.json())

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*")
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
    next()
})

const activeClients = new Map()

function isMasterAdmin(name) {
  return name === 'augustinejames' || name === 'tockdev';
}

// Broadcaster sync routine for streaming active participant rosters
function broadcastOnlineRoster() {
    const onlineUsernames = Array.from(activeClients.keys());
    const payload = JSON.stringify({ type: 'roster_update', users: onlineUsernames });
    activeClients.forEach(function(clientSocket) {
        if (clientSocket.readyState === WebSocket.OPEN) {
            clientSocket.send(payload);
        }
    });
}

app.get('/dm-contacts', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const me = decoded.username;

        const result = await db.query(`
            SELECT DISTINCT username FROM (
                SELECT receiver AS username FROM dms WHERE sender = $1
                UNION
                SELECT sender AS username FROM dms WHERE receiver = $1
            ) AS contacts WHERE username != $1;
        `, [me]);

        res.json(result.rows.map(function(row) { return row.username; }));
    } catch (err) {
        res.status(401).json({ error: 'Session expired' });
    }
});

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' })
    try {
        const hash = await bcrypt.hash(password, 10)
        await db.query('INSERT INTO users (username, password_hash) VALUES ($1, $2);', [username, hash])
        const token = jwt.sign({ username }, JWT_SECRET)
        res.json({ token, username })
    } catch (err) {
        res.status(400).json({ error: 'Username already taken' })
    }
})

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body
    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1;', [username])
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid credentials' })
        }
        const token = jwt.sign({ username }, JWT_SECRET)
        res.json({ token, username })
    } catch (err) {
        res.status(500).json({ error: 'Server authentication failure' })
    }
})

app.post('/api/change-password', async (req, res) => {
    const authHeader = req.headers.authorization;
    const { password } = req.body;
    if (!authHeader || !password) return res.status(401

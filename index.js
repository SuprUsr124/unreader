import express from 'express'
import { WebSocketServer } from 'ws'
import Database from 'better-sqlite3'
import fs from 'node:fs'

const dbExists = await fs.existsSync('chat.db')
const db = new Database('chat.db', { fileMustExist: false })
if (!dbExists) {
    db.prepare('CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, timestamp INTEGER NOT NULL, content TEXT NOT NULL);')
}

const app = express()

app.get('/', async (req, res) => {
    const index = await fs.readFileSync('static/index.html', 'utf8')
    res.send(index)
})

app.get('/history', async (req, res) => {
    const index = (req.query.index ?? 0) * 10
    const limit = 10 + index
    const messages = db.prepare('SELECT * FROM messages LIMIT ? ORDER BY timestamp DESC;')
        .all(limit).slice(index, index + 10)
    res.send(JSON.stringify(messages))
})

const wss = new WebSocketServer({ host: '0.0.0.0', port: 8080 })

wss.on('connection', (ws) => {
    ws.on('message', (msg) => {
        const body = JSON.parse(msg)
        db.prepare('INSERT INTO messages (username, timestamp, content) VALUES (?, ?, ?);')
            .run(body.username, Date.now(), body.content)
        wss.clients.forEach((c) => c.send(JSON.stringify({
            username: body.username,
            timestamp: Date.now(),
            content: body.content
        })))
    })
})

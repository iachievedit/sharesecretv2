const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Database setup
const db = new Database(path.join(__dirname, 'data', 'secrets.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    encrypted TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )
`);

// Cleanup expired secrets every 5 minutes
setInterval(() => {
  db.prepare('DELETE FROM secrets WHERE expires_at < ?').run(Date.now());
}, 5 * 60 * 1000);

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Store an encrypted secret
app.post('/api/secrets', (req, res) => {
  const { encrypted, expiresIn } = req.body;

  if (!encrypted || typeof encrypted !== 'string') {
    return res.status(400).json({ error: 'Missing encrypted data' });
  }

  // Max 50KB of encrypted data
  if (encrypted.length > 50000) {
    return res.status(400).json({ error: 'Secret too large' });
  }

  // Default 24h, max 7 days
  const maxExpiry = 7 * 24 * 60 * 60 * 1000;
  const expiry = Math.min(expiresIn || 24 * 60 * 60 * 1000, maxExpiry);

  const id = crypto.randomBytes(16).toString('hex');
  const now = Date.now();

  db.prepare('INSERT INTO secrets (id, encrypted, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .run(id, encrypted, now, now + expiry);

  res.json({ id });
});

// Retrieve and delete a secret (one-time read)
app.get('/api/secrets/:id', (req, res) => {
  const { id } = req.params;

  const secret = db.prepare('SELECT encrypted FROM secrets WHERE id = ? AND expires_at > ?')
    .get(id, Date.now());

  if (!secret) {
    return res.status(404).json({ error: 'Secret not found or already viewed' });
  }

  // Delete immediately — one-time use
  db.prepare('DELETE FROM secrets WHERE id = ?').run(id);

  res.json({ encrypted: secret.encrypted });
});

// Check if a secret exists (without retrieving it)
app.head('/api/secrets/:id', (req, res) => {
  const { id } = req.params;
  const exists = db.prepare('SELECT 1 FROM secrets WHERE id = ? AND expires_at > ?')
    .get(id, Date.now());
  res.status(exists ? 200 : 404).end();
});

// SPA fallback — serve index.html for /s/:id routes
app.get('/s/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`ShareSecret running on port ${PORT}`);
});

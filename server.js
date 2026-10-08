const express = require('express');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const db = new sqlite3('/root/elearning/platform.db');
const MEDIA_ROOT = '/mnt/yandex_disk';
const JWT_SECRET = 'changez-cette-cle-secrete-' + Date.now();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============ BASE DE DONNÉES ============
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
  );
  CREATE TABLE IF NOT EXISTS progress (
    user_id INTEGER,
    video_path TEXT,
    position REAL DEFAULT 0,
    duration REAL DEFAULT 0,
    completed INTEGER DEFAULT 0,
    archived INTEGER DEFAULT 0,
    last_watched INTEGER,
    updated_at INTEGER,
    PRIMARY KEY (user_id, video_path)
  );
  CREATE INDEX IF NOT EXISTS idx_progress_user ON progress(user_id);
`);

// ============ AUTHENTIFICATION ============
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const info = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hash);
    const token = jwt.sign({ id: info.lastInsertRowid, username }, JWT_SECRET);
    res.json({ token, username });
  } catch (e) {
    res.status(400).json({ error: 'Utilisateur existe déjà' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Identifiants invalides' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Identifiants invalides' });
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET);
  res.json({ token, username });
});

function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  const tokenFromHeader = authHeader && authHeader.split(' ')[1];
  const tokenFromQuery = req.query.token;
  const token = tokenFromHeader || tokenFromQuery;
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

// ============ DÉTECTION DES SOUS-TITRES ============
function findSubtitles(dirAbs, baseName, relDir) {
  const subtitles = [];
  const scan = (absDir, relSub) => {
    let entries;
    try { entries = fs.readdirSync(absDir); } catch { return; }
    for (const entry of entries) {
      if (!entry.toLowerCase().endsWith('.vtt')) continue;
      const entryBase = entry.slice(0, -4);
      if (entryBase === baseName || entryBase.startsWith(baseName + '.')) {
        let lang = 'default';
        if (entryBase !== baseName) {
          lang = entryBase.slice(baseName.length + 1).toLowerCase();
        }
        subtitles.push({ name: entry, lang: lang, path: path.join(relSub, entry) });
      }
    }
  };
  scan(dirAbs, relDir);
  const s1 = path.join(dirAbs, 'subtitles');
  const r1 = path.join(relDir, 'subtitles');
  if (fs.existsSync(s1) && fs.statSync(s1).isDirectory()) scan(s1, r1);
  const s2 = path.join(dirAbs, 'Subtitles');
  const r2 = path.join(relDir, 'Subtitles');
  if (fs.existsSync(s2) && fs.statSync(s2).isDirectory()) scan(s2, r2);
  subtitles.sort((a, b) => {
    if (a.lang === 'default') return -1;
    if (b.lang === 'default') return 1;
    return a.lang.localeCompare(b.lang);
  });
  return subtitles;
}

// ============ TRI INTELLIGENT ============
function extractLeadingNumber(name) {
  const base = name.replace(/\.[^.]+$/, '');
  const patterns = [
    /^(\d+(?:\.\d+)*)\s*[-–_.\):]\s*/,
    /^(?:chapitre|chapter|section|le[çc]on|lesson|part|partie|module|unit|unité|s[ée]ance|semaine|week|cours|course|video|vidéo)\s+(\d+(?:\.\d+)*)/i,
    /^(\d+(?:\.\d+)*)\s+/,
  ];
  for (const p of patterns) {
    const m = base.match(p);
    if (m) return m[1].split('.').map(Number);
  }
  return null;
}

const PRIORITY_KEYWORDS = {
  first: ['introduction','intro','bienvenue','welcome','présentation','presentation','overview','start','commencer','getting started','démarrage','demarrage','aperçu','apercu','avant-propos','préambule','preambule','sommaire','plan du cours'],
  last: ['conclusion','fin','final','résumé','resume','summary','bonus','annexe','appendix','remerciements','thank','crédits','credits','outro','wrap up','wrap-up','récapitulatif','recapitulatif','bilan']
};

function getKeywordPriority(name) {
  const lower = name.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  for (const kw of PRIORITY_KEYWORDS.first) {
    const k = kw.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    if (lower.includes(k)) return 0;
  }
  for (const kw of PRIORITY_KEYWORDS.last) {
    const k = kw.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    if (lower.includes(k)) return 50;
  }
  return 25;
}

function smartCompare(a, b) {
  if (a.type !== b.type) return a.type === 'folder' ? -1 : 1;
  const aNum = extractLeadingNumber(a.name);
  const bNum = extractLeadingNumber(b.name);
  if (aNum && bNum) {
    const len = Math.max(aNum.length, bNum.length);
    for (let i = 0; i < len; i++) {
      const av = aNum[i] !== undefined ? aNum[i] : 0;
      const bv = bNum[i] !== undefined ? bNum[i] : 0;
      if (av !== bv) return av - bv;
    }
  } else if (aNum && !bNum) {
    return -1;
  } else if (!aNum && bNum) {
    return 1;
  } else {
    const aKw = getKeywordPriority(a.name);
    const bKw = getKeywordPriority(b.name);
    if (aKw !== bKw) return aKw - bKw;
  }
  return a.name.localeCompare(b.name, 'fr', { numeric: true, sensitivity: 'base' });
}

// ============ LISTAGE DES COURS ============
const VIDEO_EXTS = ['.mp4', '.mkv', '.webm', '.avi', '.mov', '.m4v', '.ts', '.flv'];

function scanDir(dir, relPath = '') {
  const items = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return items; }
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    if (entry.name === 'subtitles' || entry.name === 'Subtitles') continue;
    const rel = path.join(relPath, entry.name);
    if (entry.isDirectory()) {
      const children = scanDir(path.join(dir, entry.name), rel);
      items.push({ type: 'folder', name: entry.name, path: rel, children });
    } else if (VIDEO_EXTS.includes(path.extname(entry.name).toLowerCase())) {
      const baseName = path.basename(entry.name, path.extname(entry.name));
      const subtitles = findSubtitles(dir, baseName, relPath);
      items.push({ type: 'video', name: entry.name, path: rel, subtitles });
    }
  }
  items.sort(smartCompare);
  return items;
}

app.get('/api/courses', auth, (req, res) => {
  res.json(scanDir(MEDIA_ROOT));
});

// ============ STREAMING VIDÉO ============
app.get('/api/stream/*', auth, (req, res) => {
  const relPath = decodeURIComponent(req.params[0]);
  const filePath = path.join(MEDIA_ROOT, relPath);
  const resolved = path.resolve(filePath);
  const root = path.resolve(MEDIA_ROOT);
  if (!resolved.startsWith(root)) return res.status(403).end();
  if (!fs.existsSync(resolved)) return res.status(404).end();
  let stat;
  try { stat = fs.statSync(resolved); } catch { return res.status(500).end(); }
  const ext = path.extname(resolved).toLowerCase();
  const mimeTypes = {
    '.mp4': 'video/mp4', '.m4v': 'video/mp4',
    '.mkv': 'video/x-matroska', '.webm': 'video/webm',
    '.avi': 'video/x-msvideo', '.mov': 'video/quicktime',
    '.ts': 'video/mp2t', '.flv': 'video/x-flv'
  };
  const contentType = mimeTypes[ext] || 'application/octet-stream';
  const range = req.headers.range;
  if (range) {
    const parts = range.replace(/bytes=/, '').split('-');
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : stat.size - 1;
    if (start >= stat.size || end >= stat.size) {
      res.writeHead(416, { 'Content-Range': `bytes */${stat.size}` });
      return res.end();
    }
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${stat.size}`,
      'Accept-Ranges': 'bytes',
      'Content-Length': end - start + 1,
      'Content-Type': contentType,
    });
    fs.createReadStream(resolved, { start, end }).pipe(res);
  } else {
    res.writeHead(200, {
      'Content-Length': stat.size,
      'Content-Type': contentType,
      'Accept-Ranges': 'bytes',
    });
    fs.createReadStream(resolved).pipe(res);
  }
});

// ============ SOUS-TITRES ============
app.get('/api/subtitle/*', auth, (req, res) => {
  const relPath = decodeURIComponent(req.params[0]);
  const filePath = path.join(MEDIA_ROOT, relPath);
  const resolved = path.resolve(filePath);
  const root = path.resolve(MEDIA_ROOT);
  if (!resolved.startsWith(root)) return res.status(403).end();
  if (!fs.existsSync(resolved)) return res.status(404).end();
  res.setHeader('Content-Type', 'text/vtt; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  fs.createReadStream(resolved).pipe(res);
});

// ============ PROGRESSION ============
app.get('/api/progress/*', auth, (req, res) => {
  const videoPath = decodeURIComponent(req.params[0]);
  const row = db.prepare('SELECT * FROM progress WHERE user_id = ? AND video_path = ?')
    .get(req.user.id, videoPath);
  res.json(row || { position: 0, duration: 0, completed: 0, archived: 0 });
});

app.post('/api/progress', auth, (req, res) => {
  const { video_path, position, duration } = req.body;
  if (!video_path || typeof position !== 'number') return res.status(400).json({ error: 'Données invalides' });
  const completed = duration > 0 && position / duration >= 0.95 ? 1 : 0;
  db.prepare(`
    INSERT INTO progress (user_id, video_path, position, duration, completed, last_watched, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, video_path) DO UPDATE SET
      position = excluded.position,
      duration = excluded.duration,
      completed = excluded.completed,
      last_watched = excluded.last_watched,
      updated_at = excluded.updated_at
  `).run(req.user.id, video_path, position, duration, completed, Date.now(), Date.now());
  res.json({ ok: true, completed });
});

app.get('/api/in-progress', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT video_path, position, duration, completed, archived, last_watched,
           CASE WHEN duration > 0 THEN ROUND(position * 100.0 / duration, 1) ELSE 0 END AS percent
    FROM progress
    WHERE user_id = ? AND archived = 0 AND position > 5
    ORDER BY last_watched DESC
  `).all(req.user.id);
  res.json(rows);
});

app.get('/api/archived', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT video_path, position, duration, completed, archived, last_watched,
           CASE WHEN duration > 0 THEN ROUND(position * 100.0 / duration, 1) ELSE 0 END AS percent
    FROM progress
    WHERE user_id = ? AND archived = 1
    ORDER BY last_watched DESC
  `).all(req.user.id);
  res.json(rows);
});

app.post('/api/archive', auth, (req, res) => {
  const { video_path, archived } = req.body;
  db.prepare(`
    INSERT INTO progress (user_id, video_path, archived, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, video_path) DO UPDATE SET
      archived = excluded.archived,
      updated_at = excluded.updated_at
  `).run(req.user.id, video_path, archived ? 1 : 0, Date.now());
  res.json({ ok: true });
});

// ============ SERVEUR ============
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Plateforme e-learning sur http://0.0.0.0:${PORT}`);
  console.log(`Media root: ${MEDIA_ROOT}`);
});
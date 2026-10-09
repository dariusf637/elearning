const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const DB_PATH = path.join(__dirname, 'platform.db');
const db = new sqlite3(DB_PATH);
const MEDIA_ROOT = process.env.MEDIA_ROOT || '/mnt/yandex_disk';
const PORT = process.env.PORT || 3000;

const CONFIG_FILE = path.join(__dirname, '.config.json');
let jwtSecret;
if (process.env.JWT_SECRET) jwtSecret = process.env.JWT_SECRET;
else if (fs.existsSync(CONFIG_FILE)) {
  try { jwtSecret = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')).jwtSecret; } catch { jwtSecret = null; }
}
if (!jwtSecret) {
  jwtSecret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({ jwtSecret }, null, 2));
  console.log('🔐 Nouveau JWT_SECRET généré dans .config.json');
}
const JWT_SECRET = jwtSecret;

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at INTEGER,
    created_by INTEGER
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
  CREATE TABLE IF NOT EXISTS favorites (
    user_id INTEGER,
    video_path TEXT,
    created_at INTEGER,
    PRIMARY KEY (user_id, video_path)
  );
  CREATE INDEX IF NOT EXISTS idx_progress_user ON progress(user_id);
  CREATE INDEX IF NOT EXISTS idx_favorites_user ON favorites(user_id);
`);

try {
  const cols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
  if (!cols.includes('role')) db.exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'");
  if (!cols.includes('created_at')) db.exec("ALTER TABLE users ADD COLUMN created_at INTEGER");
  if (!cols.includes('created_by')) db.exec("ALTER TABLE users ADD COLUMN created_by INTEGER");
} catch (e) { console.error('Migration:', e.message); }

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ============ SETUP ============
function hasAdmin() {
  return db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").get().c > 0;
}

app.get('/api/setup/status', (req, res) => {
  res.json({
    needsSetup: !hasAdmin(),
    mediaRoot: MEDIA_ROOT,
    mediaRootExists: fs.existsSync(MEDIA_ROOT),
    mediaRootHasContent: fs.existsSync(MEDIA_ROOT) && fs.readdirSync(MEDIA_ROOT).length > 0
  });
});

app.post('/api/setup/complete', async (req, res) => {
  if (hasAdmin()) return res.status(400).json({ error: 'L\'installation a déjà été effectuée.' });
  const { username, password, passwordConfirm } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs requis.' });
  if (username.length < 3) return res.status(400).json({ error: 'Nom : minimum 3 caractères.' });
  if (!/^[a-zA-Z0-9_.-]+$/.test(username)) return res.status(400).json({ error: 'Nom invalide.' });
  if (password.length < 6) return res.status(400).json({ error: 'Mot de passe : minimum 6.' });
  if (password !== passwordConfirm) return res.status(400).json({ error: 'Mots de passe différents.' });
  try {
    const hash = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)')
      .run(username, hash, 'admin', Date.now());
    console.log(`✅ Admin "${username}" créé.`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ AUTH ============
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Identifiants invalides' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Identifiants invalides' });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role || 'user' }, JWT_SECRET);
  res.json({ token, username: user.username, role: user.role || 'user' });
});

function auth(req, res, next) {
  const h = req.headers.authorization;
  const token = (h && h.split(' ')[1]) || req.query.token;
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token invalide' }); }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Accès réservé' });
  next();
}

// ============ ADMIN ============
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.role, u.created_at,
           creator.username AS created_by_name,
           (SELECT COUNT(*) FROM progress p WHERE p.user_id = u.id AND p.position > 5) AS courses_started
    FROM users u LEFT JOIN users creator ON creator.id = u.created_by
    ORDER BY u.role DESC, u.username ASC
  `).all();
  res.json(users);
});

app.post('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  if (username.length < 3) return res.status(400).json({ error: 'Nom trop court' });
  if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court' });
  const finalRole = role === 'admin' ? 'admin' : 'user';
  try {
    const hash = await bcrypt.hash(password, 10);
    const info = db.prepare('INSERT INTO users (username, password, role, created_at, created_by) VALUES (?, ?, ?, ?, ?)')
      .run(username, hash, finalRole, Date.now(), req.user.id);
    res.json({ id: info.lastInsertRowid, username, role: finalRole });
  } catch { res.status(400).json({ error: 'Utilisateur existe déjà' }); }
});

app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (id === req.user.id) return res.status(400).json({ error: 'Impossible' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'Introuvable' });
  db.prepare('DELETE FROM progress WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM favorites WHERE user_id = ?').run(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/password', auth, adminOnly, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Trop court' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'Introuvable' });
  const hash = await bcrypt.hash(password, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, id);
  res.json({ ok: true });
});

// ============ FAVORIS ============
app.get('/api/favorites', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT f.video_path, f.created_at,
           COALESCE(p.position, 0) AS position,
           COALESCE(p.duration, 0) AS duration,
           COALESCE(p.completed, 0) AS completed,
           CASE WHEN p.duration > 0 THEN ROUND(p.position * 100.0 / p.duration, 1) ELSE 0 END AS percent
    FROM favorites f
    LEFT JOIN progress p ON p.user_id = f.user_id AND p.video_path = f.video_path
    WHERE f.user_id = ?
    ORDER BY f.created_at DESC
  `).all(req.user.id);
  res.json(rows);
});

app.post('/api/favorites', auth, (req, res) => {
  const { video_path } = req.body;
  if (!video_path) return res.status(400).json({ error: 'Manquant' });
  db.prepare('INSERT OR IGNORE INTO favorites (user_id, video_path, created_at) VALUES (?, ?, ?)')
    .run(req.user.id, video_path, Date.now());
  res.json({ ok: true });
});

app.delete('/api/favorites', auth, (req, res) => {
  const { video_path } = req.body;
  if (!video_path) return res.status(400).json({ error: 'Manquant' });
  db.prepare('DELETE FROM favorites WHERE user_id = ? AND video_path = ?').run(req.user.id, video_path);
  res.json({ ok: true });
});

app.get('/api/favorites/keys', auth, (req, res) => {
  const rows = db.prepare('SELECT video_path FROM favorites WHERE user_id = ?').all(req.user.id);
  res.json(rows.map(r => r.video_path));
});

// ============ SOUS-TITRES ============
function findSubtitles(dirAbs, baseName, relDir) {
  const subtitles = [];
  const LANG_MAP = {
    'arabic':'ar','bulgarian':'bg','chinese':'zh','croatian':'hr','czech':'cs','danish':'da',
    'dutch':'nl','english':'en','estonian':'et','finnish':'fi','french':'fr','german':'de',
    'greek':'el','hebrew':'he','hindi':'hi','hungarian':'hu','indonesian':'id','italian':'it',
    'japanese':'ja','korean':'ko','latvian':'lv','lithuanian':'lt','norwegian':'no','persian':'fa',
    'polish':'pl','portuguese':'pt','romanian':'ro','russian':'ru','serbian':'sr','slovak':'sk',
    'slovenian':'sl','spanish':'es','swedish':'sv','thai':'th','turkish':'tr','ukrainian':'uk',
    'vietnamese':'vi','français':'fr','anglais':'en','espagnol':'es','allemand':'de','italien':'it',
    'portugais':'pt','russe':'ru','arabe':'ar','chinois':'zh','japonais':'ja','coréen':'ko'
  };
  function extractLang(str) {
    if (!str) return null;
    const s = str.toLowerCase().trim();
    if (/^[a-z]{2}$/.test(s)) return s;
    if (/^[a-z]{2}[-_][a-z]{2}$/.test(s)) return s.slice(0, 2);
    if (LANG_MAP[s]) return LANG_MAP[s];
    for (const [name, code] of Object.entries(LANG_MAP)) {
      if (s.startsWith(name)) return code;
    }
    return null;
  }
  const scan = (absDir, relSub) => {
    let entries;
    try { entries = fs.readdirSync(absDir); } catch { return; }
    for (const entry of entries) {
      if (!entry.toLowerCase().endsWith('.vtt')) continue;
      const entryBase = entry.slice(0, -4);
      let lang = null;
      if (entryBase === baseName) lang = 'default';
      else if (entryBase.startsWith(baseName + '.')) {
        const suffix = entryBase.slice(baseName.length + 1);
        lang = extractLang(suffix) || suffix.toLowerCase();
      } else if (entryBase.startsWith(baseName + ' ')) {
        const suffix = entryBase.slice(baseName.length + 1);
        lang = extractLang(suffix) || suffix.toLowerCase();
      } else if (entryBase.startsWith(baseName + ' - ')) {
        const suffix = entryBase.slice(baseName.length + 3);
        lang = extractLang(suffix) || suffix.toLowerCase();
      } else if (entryBase.startsWith(baseName + '_')) {
        const suffix = entryBase.slice(baseName.length + 1);
        lang = extractLang(suffix) || suffix.toLowerCase();
      }
      if (lang) subtitles.push({ name: entry, lang, path: path.join(relSub, entry) });
    }
  };
  scan(dirAbs, relDir);
  const s1 = path.join(dirAbs, 'subtitles'), r1 = path.join(relDir, 'subtitles');
  if (fs.existsSync(s1) && fs.statSync(s1).isDirectory()) scan(s1, r1);
  const s2 = path.join(dirAbs, 'Subtitles'), r2 = path.join(relDir, 'Subtitles');
  if (fs.existsSync(s2) && fs.statSync(s2).isDirectory()) scan(s2, r2);
  subtitles.sort((a, b) => {
    if (a.lang === 'default') return -1;
    if (b.lang === 'default') return 1;
    return a.lang.localeCompare(b.lang);
  });
  return subtitles;
}

// ============ QUIZ ============
function findQuiz(dirAbs, baseName, relDir) {
  const candidates = [
    { abs: path.join(dirAbs, baseName + '.quiz.json'), rel: path.join(relDir, baseName + '.quiz.json') },
    { abs: path.join(dirAbs, 'quizzes', baseName + '.json'), rel: path.join(relDir, 'quizzes', baseName + '.json') },
    { abs: path.join(dirAbs, 'quiz', baseName + '.json'), rel: path.join(relDir, 'quiz', baseName + '.json') },
  ];
  for (const c of candidates) {
    if (fs.existsSync(c.abs)) {
      try {
        const content = JSON.parse(fs.readFileSync(c.abs, 'utf8'));
        const questions = Array.isArray(content.questions) ? content.questions : [];
        const valid = questions.filter(q =>
          q && typeof q.question === 'string' &&
          Array.isArray(q.options) && q.options.length >= 2 &&
          typeof q.correct === 'number' && q.correct >= 0 && q.correct < q.options.length
        );
        if (valid.length === 0) return null;
        return { path: c.rel, count: valid.length };
      } catch (e) {
        console.error('Quiz parse error:', c.abs, e.message);
        return null;
      }
    }
  }
  return null;
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
const KW_FIRST = ['introduction','intro','bienvenue','welcome','présentation','presentation','overview','start','commencer','getting started','démarrage','demarrage','aperçu','apercu','avant-propos','préambule','preambule','sommaire','plan du cours'];
const KW_LAST = ['conclusion','fin','final','résumé','resume','summary','bonus','annexe','appendix','remerciements','thank','crédits','credits','outro','wrap up','wrap-up','récapitulatif','recapitulatif','bilan'];
function getKwPriority(name) {
  const lower = name.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  for (const kw of KW_FIRST) {
    const k = kw.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    if (lower.includes(k)) return 0;
  }
  for (const kw of KW_LAST) {
    const k = kw.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    if (lower.includes(k)) return 50;
  }
  return 25;
}
function smartCompare(a, b) {
  if (a.type !== b.type) {
    const order = { folder: 0, video: 1, document: 2 };
    return (order[a.type] ?? 3) - (order[b.type] ?? 3);
  }
  const an = extractLeadingNumber(a.name), bn = extractLeadingNumber(b.name);
  if (an && bn) {
    const len = Math.max(an.length, bn.length);
    for (let i = 0; i < len; i++) {
      const av = an[i] !== undefined ? an[i] : 0;
      const bv = bn[i] !== undefined ? bn[i] : 0;
      if (av !== bv) return av - bv;
    }
  } else if (an && !bn) return -1;
  else if (!an && bn) return 1;
  else {
    const ap = getKwPriority(a.name), bp = getKwPriority(b.name);
    if (ap !== bp) return ap - bp;
  }
  return a.name.localeCompare(b.name, 'fr', { numeric: true, sensitivity: 'base' });
}

// ============ SCAN ============
const VIDEO_EXTS = ['.mp4', '.mkv', '.webm', '.avi', '.mov', '.m4v', '.ts', '.flv'];
const DOC_EXTS = ['.pdf'];

function scanDir(dir, relPath = '') {
  const items = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return items; }
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    if (['subtitles', 'Subtitles', 'quiz', 'quizzes'].includes(entry.name)) continue;
    const rel = path.join(relPath, entry.name);
    if (entry.isDirectory()) {
      const children = scanDir(path.join(dir, entry.name), rel);
      items.push({ type: 'folder', name: entry.name, path: rel, children });
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      if (VIDEO_EXTS.includes(ext)) {
        const baseName = path.basename(entry.name, path.extname(entry.name));
        const subtitles = findSubtitles(dir, baseName, relPath);
        const quiz = findQuiz(dir, baseName, relPath);
        items.push({ type: 'video', name: entry.name, path: rel, subtitles, quiz });
      } else if (DOC_EXTS.includes(ext)) {
        items.push({ type: 'document', name: entry.name, path: rel, ext });
      }
    }
  }
  items.sort(smartCompare);
  return items;
}

const folderCache = new Map();
const CACHE_TTL = 120000;
function countVideosIn(dir) {
  const now = Date.now();
  const c = folderCache.get(dir);
  if (c && now - c.time < CACHE_TTL) return c.data;
  let videoCount = 0;
  const walk = (d) => {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name.startsWith('.') || ['subtitles','Subtitles','quiz','quizzes'].includes(e.name)) continue;
      if (e.isDirectory()) walk(path.join(d, e.name));
      else if (VIDEO_EXTS.includes(path.extname(e.name).toLowerCase())) videoCount++;
    }
  };
  walk(dir);
  const data = { videoCount };
  folderCache.set(dir, { time: now, data });
  return data;
}

// ============ AGRÉGATION ============
function likeEscape(str) {
  return str.replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_');
}
function getCourseStats(userId) {
  const folders = [];
  try {
    const entries = fs.readdirSync(MEDIA_ROOT, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
      const abs = path.join(MEDIA_ROOT, entry.name);
      const stats = countVideosIn(abs);
      const videoCount = stats.videoCount;
      const likePattern = likeEscape(entry.name) + '/%';
      const prog = db.prepare(`
        SELECT COUNT(*) AS total_touched,
               SUM(CASE WHEN completed = 1 THEN 1 ELSE 0 END) AS total_completed,
               MAX(last_watched) AS last_watched
        FROM progress WHERE user_id = ? AND video_path LIKE ? ESCAPE '\\'
      `).get(userId, likePattern);
      const lastVid = db.prepare(`
        SELECT video_path FROM progress
        WHERE user_id = ? AND video_path LIKE ? ESCAPE '\\' AND position > 5 AND completed = 0
        ORDER BY last_watched DESC LIMIT 1
      `).get(userId, likePattern);
      const completed = prog.total_completed || 0;
      const started = prog.total_touched || 0;
      const percent = videoCount > 0 ? Math.round(completed * 100 / videoCount) : 0;
      const isFullyDone = videoCount > 0 && completed === videoCount;
      const hasStarted = started > 0;
      folders.push({
        type: 'folder', name: entry.name, path: entry.name,
        videoCount, started, completed,
        lastWatched: prog.last_watched || 0,
        lastVideoPath: lastVid ? lastVid.video_path : null,
        percent, isFullyDone, hasStarted
      });
    }
  } catch (e) { console.error(e); }
  return folders;
}

// ============ ROUTES ============
app.get('/api/courses/top', auth, (req, res) => {
  const folders = getCourseStats(req.user.id);
  folders.sort(smartCompare);
  res.json(folders);
});

app.get('/api/in-progress', auth, (req, res) => {
  const folders = getCourseStats(req.user.id);
  const filtered = folders.filter(c => c.hasStarted && !c.isFullyDone)
    .sort((a, b) => b.lastWatched - a.lastWatched);
  res.json(filtered);
});

app.get('/api/completed', auth, (req, res) => {
  const folders = getCourseStats(req.user.id);
  const filtered = folders.filter(c => c.isFullyDone)
    .sort((a, b) => b.lastWatched - a.lastWatched);
  res.json(filtered);
});

app.get('/api/resume', auth, (req, res) => {
  const folders = getCourseStats(req.user.id);
  const filtered = folders.filter(c => c.hasStarted && !c.isFullyDone)
    .sort((a, b) => b.lastWatched - a.lastWatched).slice(0, 4);
  res.json(filtered);
});

app.get('/api/courses', auth, (req, res) => {
  res.json(scanDir(MEDIA_ROOT));
});

app.get('/api/courses/detail/*', auth, (req, res) => {
  const rel = decodeURIComponent(req.params[0]);
  const abs = path.join(MEDIA_ROOT, rel);
  if (!path.resolve(abs).startsWith(path.resolve(MEDIA_ROOT))) return res.status(403).end();
  if (!fs.existsSync(abs)) return res.status(404).json({ error: 'Dossier introuvable' });
  res.json(scanDir(abs, rel));
});

app.get('/api/search', auth, (req, res) => {
  const q = (req.query.q || '').toLowerCase().trim();
  if (q.length < 2) return res.json({ courses: [], lessons: [] });
  const all = scanDir(MEDIA_ROOT);
  const courses = [], lessons = [];
  const walk = (items, courseName) => {
    for (const it of items) {
      if (it.type === 'folder') walk(it.children, courseName || it.name);
      else if (it.name.toLowerCase().includes(q)) {
        lessons.push({ name: it.name, path: it.path, course: courseName, isDoc: it.type === 'document' });
      }
    }
  };
  for (const item of all) {
    if (item.type === 'folder') {
      if (item.name.toLowerCase().includes(q)) courses.push({ name: item.name, path: item.path });
      walk(item.children, item.name);
    }
  }
  res.json({ courses: courses.slice(0, 10), lessons: lessons.slice(0, 30) });
});

app.get('/api/archived', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT video_path, position, duration, completed, archived, last_watched,
           CASE WHEN duration > 0 THEN ROUND(position * 100.0 / duration, 1) ELSE 0 END AS percent
    FROM progress WHERE user_id = ? AND archived = 1 ORDER BY last_watched DESC
  `).all(req.user.id);
  res.json(rows);
});

// ============ STREAMING ============
app.get('/api/stream/*', auth, (req, res) => {
  const rel = decodeURIComponent(req.params[0]);
  const resolved = path.resolve(path.join(MEDIA_ROOT, rel));
  const root = path.resolve(MEDIA_ROOT);
  if (!resolved.startsWith(root) || !fs.existsSync(resolved)) return res.status(404).end();
  let stat;
  try { stat = fs.statSync(resolved); } catch { return res.status(500).end(); }
  const ext = path.extname(resolved).toLowerCase();
  const mimes = {'.mp4':'video/mp4','.m4v':'video/mp4','.mkv':'video/x-matroska','.webm':'video/webm','.avi':'video/x-msvideo','.mov':'video/quicktime','.ts':'video/mp2t','.flv':'video/x-flv'};
  const ct = mimes[ext] || 'application/octet-stream';
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
      'Content-Type': ct,
    });
    fs.createReadStream(resolved, { start, end }).pipe(res);
  } else {
    res.writeHead(200, { 'Content-Length': stat.size, 'Content-Type': ct, 'Accept-Ranges': 'bytes' });
    fs.createReadStream(resolved).pipe(res);
  }
});

// ============ DOCUMENTS (PDF) ============
app.get('/api/document/*', auth, (req, res) => {
  const rel = decodeURIComponent(req.params[0]);
  const resolved = path.resolve(path.join(MEDIA_ROOT, rel));
  const root = path.resolve(MEDIA_ROOT);
  if (!resolved.startsWith(root) || !fs.existsSync(resolved)) return res.status(404).end();
  const ext = path.extname(resolved).toLowerCase();
  const mimes = {
    '.pdf': 'application/pdf',
    '.txt': 'text/plain; charset=utf-8',
    '.md': 'text/plain; charset=utf-8'
  };
  const ct = mimes[ext] || 'application/octet-stream';
  res.setHeader('Content-Type', ct);
  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  fs.createReadStream(resolved).pipe(res);
});

app.get('/api/subtitle/*', auth, (req, res) => {
  const rel = decodeURIComponent(req.params[0]);
  const resolved = path.resolve(path.join(MEDIA_ROOT, rel));
  const root = path.resolve(MEDIA_ROOT);
  if (!resolved.startsWith(root) || !fs.existsSync(resolved)) return res.status(404).end();
  res.setHeader('Content-Type', 'text/vtt; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  fs.createReadStream(resolved).pipe(res);
});

app.get('/api/quiz/*', auth, (req, res) => {
  const rel = decodeURIComponent(req.params[0]);
  const resolved = path.resolve(path.join(MEDIA_ROOT, rel));
  const root = path.resolve(MEDIA_ROOT);
  if (!resolved.startsWith(root) || !fs.existsSync(resolved)) return res.status(404).end();
  try {
    const content = JSON.parse(fs.readFileSync(resolved, 'utf8'));
    res.json(content);
  } catch (e) { res.status(500).json({ error: 'Quiz invalide' }); }
});

// ============ PROGRESSION ============
app.get('/api/progress/*', auth, (req, res) => {
  const vp = decodeURIComponent(req.params[0]);
  const row = db.prepare('SELECT * FROM progress WHERE user_id = ? AND video_path = ?').get(req.user.id, vp);
  res.json(row || { position: 0, duration: 0, completed: 0, archived: 0 });
});

app.post('/api/progress', auth, (req, res) => {
  const { video_path, position, duration } = req.body;
  if (!video_path || typeof position !== 'number') return res.status(400).json({ error: 'Invalide' });
  const completed = duration > 0 && position / duration >= 0.95 ? 1 : 0;
  db.prepare(`
    INSERT INTO progress (user_id, video_path, position, duration, completed, last_watched, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, video_path) DO UPDATE SET
      position = excluded.position, duration = excluded.duration,
      completed = excluded.completed, last_watched = excluded.last_watched,
      updated_at = excluded.updated_at
  `).run(req.user.id, video_path, position, duration, completed, Date.now(), Date.now());
  res.json({ ok: true, completed });
});

app.post('/api/archive', auth, (req, res) => {
  const { video_path, archived } = req.body;
  db.prepare(`
    INSERT INTO progress (user_id, video_path, archived, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, video_path) DO UPDATE SET
      archived = excluded.archived, updated_at = excluded.updated_at
  `).run(req.user.id, video_path, archived ? 1 : 0, Date.now());
  res.json({ ok: true });
});

// ============ SERVEUR ============
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Plateforme e-learning sur http://0.0.0.0:${PORT}`);
  console.log(`📁 Media root: ${MEDIA_ROOT}`);
  console.log(`💾 Base: ${DB_PATH}`);
  if (!hasAdmin()) console.log(`\n⚠️  Aucun administrateur. Ouvrez http://localhost:${PORT}\n`);
  else console.log(`✅ Prêt.\n`);
});

process.on('SIGINT', () => {
  console.log('\n👋 Fermeture…');
  try { db.close(); } catch {}
  process.exit(0);
});
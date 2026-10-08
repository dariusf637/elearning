-- ============================================
-- Schéma de la base de données - Ma Plateforme
-- ============================================
-- Ce fichier documente la structure de la base.
-- Il est exécuté automatiquement par server.js au démarrage
-- et par init-db.js pour une initialisation manuelle.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
  created_by INTEGER,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Table de progression
CREATE TABLE IF NOT EXISTS progress (
  user_id INTEGER NOT NULL,
  video_path TEXT NOT NULL,
  position REAL DEFAULT 0,
  duration REAL DEFAULT 0,
  completed INTEGER DEFAULT 0 CHECK(completed IN (0, 1)),
  archived INTEGER DEFAULT 0 CHECK(archived IN (0, 1)),
  last_watched INTEGER,
  updated_at INTEGER,
  PRIMARY KEY (user_id, video_path),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_progress_user ON progress(user_id);
CREATE INDEX IF NOT EXISTS idx_progress_last_watched ON progress(user_id, last_watched DESC);
CREATE INDEX IF NOT EXISTS idx_progress_completed ON progress(user_id, completed);
CREATE INDEX IF NOT EXISTS idx_progress_archived ON progress(user_id, archived);
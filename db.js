const Database = require("better-sqlite3");

const dbPath = process.env.DB_PATH || "./guild.db";
const db = new Database(dbPath);

// Init schema
db.exec(`
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nickname TEXT NOT NULL UNIQUE,
  points_total INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'OPEN',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS bids (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL,
  member_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS holds (
  item_id INTEGER PRIMARY KEY,
  member_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  member_id INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS finals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL UNIQUE,
  winner_member_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  finalized_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings(key, value) VALUES('bid_deadline_utc', '');
`);

// --- MIGRATION: add holds.created_at if missing (for existing DB) ---
try {
  db.exec("ALTER TABLE holds ADD COLUMN created_at TEXT NOT NULL DEFAULT (datetime('now'))");
} catch (_) {
  // ignore (already exists)
}

// Seed contoh (hapus kalau tidak perlu)
const seedMember = db.prepare("INSERT OR IGNORE INTO members(nickname, points_total) VALUES(?, ?)");
["Lucier"].forEach((n, i) => seedMember.run(n, 160 + i * 20));

module.exports = db;

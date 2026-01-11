const Database = require("better-sqlite3");
const db = new Database("guild.db");

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
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(item_id) REFERENCES items(id),
  FOREIGN KEY(member_id) REFERENCES members(id)
);

CREATE TABLE IF NOT EXISTS holds (
  item_id INTEGER PRIMARY KEY,
  member_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  FOREIGN KEY(item_id) REFERENCES items(id),
  FOREIGN KEY(member_id) REFERENCES members(id)
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  member_id INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(member_id) REFERENCES members(id)
);

-- ✅ Finalize results (hasil pemenang final)
CREATE TABLE IF NOT EXISTS finals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL UNIQUE,
  winner_member_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  finalized_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(item_id) REFERENCES items(id),
  FOREIGN KEY(winner_member_id) REFERENCES members(id)
);

-- ✅ Global settings (deadline close bid)
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings(key, value) VALUES('bid_deadline_utc', '');
`);

// Seed contoh (hapus kalau tidak perlu)
const seedMember = db.prepare("INSERT OR IGNORE INTO members(nickname, points_total) VALUES(?, ?)");
["Montana"].forEach((n, i) => seedMember.run(n, 160 + i * 20));

const seedItem = db.prepare("INSERT OR IGNORE INTO items(name, status) VALUES(?, 'OPEN')");
["Blueprint"].forEach((it) => seedItem.run(it));

module.exports = db;

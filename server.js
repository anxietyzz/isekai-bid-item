// ========================= GUILD BID SYSTEM (FULL MERGED + CSV ADMIN MENU) =========================
// ✅ Deadline pakai 1 input date picker (datetime-local) seperti gambar
// ✅ Semua logika waktu "FLAT UTC+7/WIB" (bukan local timezone)
// ✅ Disimpan ke server sebagai ISO UTC berakhiran "Z" (stabil & sama seperti skrip lama)
// ✅ Dashboard sections bisa minimize: Member Points / Items - Highest Bid / Final Results
// ✅ (ADDED BACK) Admin menu Import/Export CSV (Google Sheet CSV + Export snapshot)
// ==================================================================================================

const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const db = require("./db");

const app = express();
app.use(express.json());
app.use(cookieParser());

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123"; // ganti via ENV

// ===================== (ADDED) Default CSV URLs =====================
const DEFAULT_MEMBERS_CSV_URL =
  process.env.MEMBERS_CSV_URL ||
  "https://docs.google.com/spreadsheets/d/17EytQeecsHLA7XfwVZyNsyN7k1S9lmkWxDVyS3lGOO8/export?format=csv&gid=0";

const DEFAULT_ITEMS_CSV_URL =
  process.env.ITEMS_CSV_URL ||
  "https://docs.google.com/spreadsheets/d/17EytQeecsHLA7XfwVZyNsyN7k1S9lmkWxDVyS3lGOO8/export?format=csv&gid=1041003630";

// (optional) fallback fetch untuk Node < 18 (tidak mengganggu kalau Node 18+)
let _fetch = global.fetch;
if (!_fetch) {
  try {
    _fetch = require("node-fetch");
  } catch (e) {
    _fetch = null;
  }
}

// ====================== Session helpers ======================
function createSession(member_id, hours = 72) {
  const token = crypto.randomBytes(24).toString("hex");
  const expires = new Date(Date.now() + hours * 3600 * 1000).toISOString();
  db.prepare("INSERT INTO sessions(token, member_id, expires_at) VALUES(?, ?, ?)").run(
    token,
    member_id,
    expires
  );
  return token;
}

function getSession(req) {
  const token = req.cookies?.sid;
  if (!token) return null;
  return (
    db
      .prepare("SELECT * FROM sessions WHERE token=? AND expires_at > datetime('now')")
      .get(token) || null
  );
}

function requireLogin(req, res, next) {
  const s = getSession(req);
  if (!s) return res.redirect("/login");
  req.session = s;
  next();
}

function requireLoginApi(req, res, next) {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Belum login." });
  req.session = s;
  next();
}

// ====================== Admin auth ======================
function isAdmin(req) {
  return req.cookies?.admin === "1";
}
function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(403).json({ error: "Admin only." });
  next();
}

// ====================== Points helpers ======================
function getHeldByMember(memberId) {
  return db
    .prepare("SELECT COALESCE(SUM(amount),0) AS held FROM holds WHERE member_id=?")
    .get(memberId).held;
}
function getAvailablePoints(memberId) {
  const total = db.prepare("SELECT points_total FROM members WHERE id=?").get(memberId)
    .points_total;
  return total - getHeldByMember(memberId);
}
function getCurrentHold(itemId) {
  return db.prepare("SELECT * FROM holds WHERE item_id=?").get(itemId);
}

// ====================== Settings helpers (robust) ======================
function getSetting(key) {
  return db.prepare("SELECT value FROM settings WHERE key=?").get(key)?.value || "";
}
function setSetting(key, value) {
  const exist = db.prepare("SELECT 1 FROM settings WHERE key=?").get(key);
  if (exist) db.prepare("UPDATE settings SET value=? WHERE key=?").run(value, key);
  else db.prepare("INSERT INTO settings(key,value) VALUES(?,?)").run(key, value);
}

// init default key
(function bootstrap() {
  // (ADDED) init import urls
  if (!getSetting("members_csv_url")) setSetting("members_csv_url", DEFAULT_MEMBERS_CSV_URL);
  if (!getSetting("items_csv_url")) setSetting("items_csv_url", DEFAULT_ITEMS_CSV_URL);

  if (db.prepare("SELECT 1 FROM settings WHERE key='bid_deadline_utc'").get() == null) {
    setSetting("bid_deadline_utc", "");
  }
})();

// ====================== Deadline helpers ======================
function getDeadlineUtc() {
  return getSetting("bid_deadline_utc") || "";
}
function getDeadlineIsoOrNull() {
  const v = getDeadlineUtc();
  if (!v) return null;
  const t = Date.parse(v);
  if (Number.isNaN(t)) return null;
  return new Date(t).toISOString();
}
function isBidClosedByDeadline() {
  const v = getDeadlineUtc();
  if (!v) return false;

  let t = Date.parse(v);

  // fallback ISO tanpa timezone -> paksa Z
  if (Number.isNaN(t)) {
    const looksIsoNoTz =
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(v) &&
      !(/[zZ]|[+\-]\d{2}:\d{2}$/.test(v));
    if (looksIsoNoTz) t = Date.parse(v + "Z");
  }

  if (Number.isNaN(t)) return false;
  return Date.now() >= t;
}

// ====================== Auto finalize after deadline ======================
function autoFinalizeAllIfDeadlinePassed() {
  if (!isBidClosedByDeadline()) return { ran: false, finalized: 0 };

  const deadlineIso = getDeadlineIsoOrNull() || new Date().toISOString();

  const rows = db.prepare(`
    SELECT i.id AS item_id, i.name AS item_name,
           h.member_id AS winner_member_id, h.amount AS amount
    FROM items i
    JOIN holds h ON h.item_id = i.id
    LEFT JOIN finals f ON f.item_id = i.id
    WHERE i.status = 'OPEN' AND f.item_id IS NULL
    ORDER BY i.created_at DESC
  `).all();

  const tx = db.transaction(() => {
    for (const r of rows) {
      db.prepare(`UPDATE items SET status='CLOSED' WHERE id=?`).run(r.item_id);
      db.prepare(`UPDATE members SET points_total = points_total - ? WHERE id=?`).run(
        r.amount,
        r.winner_member_id
      );
      db.prepare(`
        INSERT INTO finals(item_id, winner_member_id, amount, finalized_at)
        VALUES(?, ?, ?, ?)
      `).run(r.item_id, r.winner_member_id, r.amount, deadlineIso);
      db.prepare(`DELETE FROM holds WHERE item_id=?`).run(r.item_id);
    }

    // tutup semua item OPEN yang tersisa (yang tidak punya hold)
    db.prepare(`UPDATE items SET status='CLOSED' WHERE status='OPEN'`).run();
  });

  tx();
  return { ran: true, finalized: rows.length };
}

// ====================== (ADDED) CSV helpers ======================
async function fetchText(url) {
  const f = _fetch || global.fetch;
  if (!f) throw new Error("fetch tidak tersedia. Pakai Node 18+ atau install node-fetch.");
  const r = await f(url, { redirect: "follow" });
  if (!r.ok) throw new Error("Fetch gagal (" + r.status + ")");
  return await r.text();
}

// CSV parser sederhana (quoted)
function parseCsv(text) {
  const rows = [];
  let row = [];
  let cur = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (ch === '"' && inQuotes && next === '"') {
      cur += '"';
      i++;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (!inQuotes && ch === ",") {
      row.push(cur.trim());
      cur = "";
      continue;
    }
    if (!inQuotes && (ch === "\n" || ch === "\r")) {
      if (ch === "\r" && next === "\n") i++;
      row.push(cur.trim());
      cur = "";
      if (row.some((v) => v !== "")) rows.push(row);
      row = [];
      continue;
    }
    cur += ch;
  }
  if (cur.length || row.length) {
    row.push(cur.trim());
    if (row.some((v) => v !== "")) rows.push(row);
  }
  return rows;
}

function toHeaderMap(headerRow) {
  const map = {};
  headerRow.forEach((h, idx) => {
    const key = String(h || "").toLowerCase().trim();
    if (key) map[key] = idx;
  });
  return map;
}

function pick(row, map, keys) {
  for (const k of keys) {
    const idx = map[k];
    if (idx != null) return String(row[idx] ?? "").trim();
  }
  return "";
}

function pickByIndex(row, idx, fallback = "") {
  if (!row || idx < 0) return fallback;
  const v = row[idx];
  return String(v ?? fallback).trim();
}

function csvEscape(v) {
  const s = String(v ?? "");
  if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

// ====================== API base ======================
app.get("/api/members", (req, res) => {
  res.json(db.prepare("SELECT id, nickname, points_total FROM members ORDER BY nickname").all());
});

app.get("/api/items", (req, res) => {
  res.json(db.prepare("SELECT id, name, status FROM items ORDER BY created_at DESC").all());
});

app.get("/api/me", (req, res) => {
  const s = getSession(req);
  if (!s) return res.json({ logged_in: false });

  try {
    autoFinalizeAllIfDeadlinePassed();
  } catch (e) {}

  const m = db.prepare("SELECT id, nickname, points_total FROM members WHERE id=?").get(s.member_id);
  if (!m) return res.json({ logged_in: false });

  const held = getHeldByMember(m.id);
  res.json({
    logged_in: true,
    is_admin: isAdmin(req),
    bid_closed: isBidClosedByDeadline(),
    bid_deadline_utc: getDeadlineUtc() || "",
    member: {
      id: m.id,
      nickname: m.nickname,
      points_total: m.points_total,
      held_points: held,
      available_points: m.points_total - held,
    },
  });
});

// ====================== Login / Logout ======================
app.post("/api/login", (req, res) => {
  const { nickname } = req.body;
  if (!nickname) return res.status(400).json({ error: "Nickname wajib." });

  const member = db.prepare("SELECT * FROM members WHERE nickname=?").get(nickname);
  if (!member) return res.status(404).json({ error: "Member tidak ditemukan." });

  const token = createSession(member.id, 72);
  res.cookie("sid", token, { httpOnly: true, sameSite: "lax" });
  res.clearCookie("admin");
  res.json({ ok: true });
});

app.post("/api/admin/login", requireLoginApi, (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password admin wajib." });
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: "Password admin salah." });

  res.cookie("admin", "1", { httpOnly: true, sameSite: "lax" });
  res.json({ ok: true, message: "Admin mode aktif." });
});

app.post("/api/admin/logout", requireLoginApi, (req, res) => {
  res.clearCookie("admin");
  res.json({ ok: true, message: "Admin mode nonaktif." });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies?.sid;
  if (token) db.prepare("DELETE FROM sessions WHERE token=?").run(token);
  res.clearCookie("sid");
  res.clearCookie("admin");
  res.json({ ok: true });
});

// ====================== Dashboard ======================
app.get("/api/dashboard", requireLoginApi, (req, res) => {
  try {
    autoFinalizeAllIfDeadlinePassed();
  } catch (e) {}

  const members = db.prepare(`
    SELECT m.id, m.nickname, m.points_total,
      COALESCE((SELECT SUM(h.amount) FROM holds h WHERE h.member_id = m.id), 0) AS held_points
    FROM members m
    ORDER BY m.nickname
  `).all();

  const items = db.prepare(`
    SELECT i.id, i.name, i.status,
      h.amount AS highest_amount,
      mm.nickname AS highest_nickname,
      (SELECT MAX(b.created_at) FROM bids b WHERE b.item_id = i.id) AS highest_time
    FROM items i
    LEFT JOIN holds h ON h.item_id = i.id
    LEFT JOIN members mm ON mm.id = h.member_id
    ORDER BY i.created_at DESC
  `).all();

  const finals = db.prepare(`
    SELECT i.name AS item_name, m.nickname AS winner, f.amount, f.finalized_at
    FROM finals f
    JOIN items i ON i.id = f.item_id
    JOIN members m ON m.id = f.winner_member_id
    ORDER BY f.finalized_at DESC
  `).all();

  res.json({
    bid_closed: isBidClosedByDeadline(),
    bid_deadline_utc: getDeadlineUtc() || "",
    members: members.map((x) => ({ ...x, available_points: x.points_total - x.held_points })),
    items,
    finals,
  });
});

// ====================== Bid ======================
app.post("/api/bid", requireLoginApi, (req, res) => {
  try {
    autoFinalizeAllIfDeadlinePassed();
  } catch (e) {}

  if (isBidClosedByDeadline()) {
    return res.status(403).json({ error: "Bid sudah ditutup karena melewati deadline." });
  }

  const { itemName, amount } = req.body;
  if (!itemName || !Number.isInteger(amount))
    return res.status(400).json({ error: "itemName dan amount (integer) wajib." });
  if (amount < 1) return res.status(400).json({ error: "Bid minimal 1." });

  const member = db.prepare("SELECT * FROM members WHERE id=?").get(req.session.member_id);
  const item = db.prepare("SELECT * FROM items WHERE name=?").get(itemName);

  if (!member) return res.status(404).json({ error: "Member tidak ditemukan." });
  if (!item) return res.status(404).json({ error: "Item tidak ditemukan." });
  if (item.status !== "OPEN") return res.status(400).json({ error: "Lelang item sudah ditutup." });

  const finalized = db.prepare("SELECT 1 FROM finals WHERE item_id=?").get(item.id);
  if (finalized) return res.status(400).json({ error: "Item sudah finalized." });

  const currentHold = getCurrentHold(item.id);
  const currentHighest = currentHold ? currentHold.amount : 0;
  if (amount <= currentHighest)
    return res.status(400).json({ error: "Bid harus lebih tinggi dari " + currentHighest + "." });

  const available = getAvailablePoints(member.id);
  if (amount > available)
    return res.status(400).json({ error: "Poin tidak cukup. Available kamu: " + available + "." });

  const tx = db.transaction(() => {
    db.prepare("INSERT INTO bids(item_id, member_id, amount) VALUES(?, ?, ?)").run(
      item.id,
      member.id,
      amount
    );
    if (currentHold) db.prepare("DELETE FROM holds WHERE item_id=?").run(item.id);
    db.prepare("INSERT INTO holds(item_id, member_id, amount) VALUES(?, ?, ?)").run(
      item.id,
      member.id,
      amount
    );
  });

  try {
    tx();
  } catch (e) {
    return res.status(500).json({ error: "Gagal proses bid.", detail: String(e.message || e) });
  }

  res.json({ ok: true, message: "Bid diterima. Kamu jadi pemenang sementara." });
});

// ====================== ADMIN: deadline set/clear ======================
// ⚠️ Referensi dari skrip lama: server hanya mau ISO yang valid.
// Kita simpan normalisasi toISOString() (pasti berakhiran Z).
app.post("/api/admin/set-deadline", requireLoginApi, requireAdmin, (req, res) => {
  const { deadline_utc } = req.body;
  if (typeof deadline_utc !== "string")
    return res.status(400).json({ error: "deadline_utc wajib string ISO." });

  const v = deadline_utc.trim();

  if (v !== "") {
    const t = Date.parse(v);
    if (Number.isNaN(t)) return res.status(400).json({ error: "deadline_utc tidak valid (ISO)." });

    const normalized = new Date(t).toISOString(); // ✅ pasti ...Z
    setSetting("bid_deadline_utc", normalized);
    return res.json({ ok: true, message: "Deadline disimpan." });
  }

  setSetting("bid_deadline_utc", "");
  res.json({ ok: true, message: "Deadline dikosongkan." });
});

// ====================== ADMIN: add / delete member & item ======================
app.post("/api/admin/add-member", requireLoginApi, requireAdmin, (req, res) => {
  const { nickname, points_total = 0 } = req.body;
  if (!nickname || typeof nickname !== "string")
    return res.status(400).json({ error: "nickname wajib (string)." });

  const clean = nickname.trim();
  if (clean.length < 2) return res.status(400).json({ error: "nickname terlalu pendek." });
  if (!Number.isInteger(points_total) || points_total < 0)
    return res.status(400).json({ error: "points_total harus integer >= 0." });

  try {
    db.prepare("INSERT INTO members(nickname, points_total) VALUES(?, ?)").run(clean, points_total);
  } catch (e) {
    return res.status(400).json({
      error: "Gagal menambah member (mungkin nickname sudah ada).",
      detail: String(e.message || e),
    });
  }
  res.json({ ok: true, message: "Member " + clean + " ditambahkan." });
});

app.post("/api/admin/delete-member", requireLoginApi, requireAdmin, (req, res) => {
  const { nickname } = req.body;
  if (!nickname) return res.status(400).json({ error: "nickname wajib." });

  const m = db.prepare("SELECT * FROM members WHERE nickname=?").get(nickname);
  if (!m) return res.status(404).json({ error: "Member tidak ditemukan." });

  const hasHold = db.prepare("SELECT 1 FROM holds WHERE member_id=?").get(m.id);
  const hasBid = db.prepare("SELECT 1 FROM bids WHERE member_id=?").get(m.id);
  const hasFinal = db.prepare("SELECT 1 FROM finals WHERE winner_member_id=?").get(m.id);

  if (hasHold || hasBid || hasFinal) {
    return res.status(400).json({ error: "Tidak bisa hapus member: sudah punya bid/hold/final." });
  }

  db.prepare("DELETE FROM members WHERE id=?").run(m.id);
  res.json({ ok: true, message: "Member " + nickname + " dihapus." });
});

app.post("/api/admin/set-points", requireLoginApi, requireAdmin, (req, res) => {
  const { nickname, points_total } = req.body;
  if (!nickname || !Number.isInteger(points_total) || points_total < 0) {
    return res.status(400).json({ error: "nickname dan points_total (integer >= 0) wajib." });
  }

  const m = db.prepare("SELECT * FROM members WHERE nickname=?").get(nickname);
  if (!m) return res.status(404).json({ error: "Member tidak ditemukan." });

  const held = getHeldByMember(m.id);
  if (points_total < held)
    return res.status(400).json({ error: "Tidak bisa set poin < held (" + held + ")." });

  db.prepare("UPDATE members SET points_total=? WHERE id=?").run(points_total, m.id);
  res.json({ ok: true, message: "Poin " + nickname + " di-set menjadi " + points_total + "." });
});

app.post("/api/admin/add-item", requireLoginApi, requireAdmin, (req, res) => {
  const { name } = req.body;
  if (!name || typeof name !== "string") return res.status(400).json({ error: "name wajib (string)." });

  const clean = name.trim();
  if (clean.length < 2) return res.status(400).json({ error: "nama item terlalu pendek." });

  try {
    db.prepare("INSERT INTO items(name, status) VALUES(?, 'OPEN')").run(clean);
  } catch (e) {
    return res.status(400).json({
      error: "Gagal menambah item (mungkin item sudah ada).",
      detail: String(e.message || e),
    });
  }
  res.json({ ok: true, message: "Item " + clean + " ditambahkan (OPEN)." });
});

app.post("/api/admin/delete-item", requireLoginApi, requireAdmin, (req, res) => {
  const { itemName } = req.body;
  if (!itemName) return res.status(400).json({ error: "itemName wajib." });

  const item = db.prepare("SELECT * FROM items WHERE name=?").get(itemName);
  if (!item) return res.status(404).json({ error: "Item tidak ditemukan." });

  const hasHold = db.prepare("SELECT 1 FROM holds WHERE item_id=?").get(item.id);
  const hasBid = db.prepare("SELECT 1 FROM bids WHERE item_id=?").get(item.id);
  const hasFinal = db.prepare("SELECT 1 FROM finals WHERE item_id=?").get(item.id);

  if (hasHold || hasBid || hasFinal) {
    return res.status(400).json({ error: "Tidak bisa hapus item: sudah punya bid/hold/final." });
  }

  db.prepare("DELETE FROM items WHERE id=?").run(item.id);
  res.json({ ok: true, message: "Item " + itemName + " dihapus." });
});

app.post("/api/admin/delete-all-items", requireLoginApi, requireAdmin, (req, res) => {
  const confirm = req.query?.confirm;
  if (confirm !== "YES") {
    return res.status(400).json({ error: "Tambahkan ?confirm=YES untuk menghapus SEMUA items/bids/holds/finals." });
  }

  const tx = db.transaction(() => {
    db.prepare("DELETE FROM holds").run();
    db.prepare("DELETE FROM bids").run();
    db.prepare("DELETE FROM finals").run();
    db.prepare("DELETE FROM items").run();
  });

  try { tx(); }
  catch (e) { return res.status(500).json({ error: "Gagal delete all items.", detail: String(e.message || e) }); }

  res.json({ ok: true, message: "Semua items + bids + holds + finals sudah dihapus." });
});

app.post("/api/admin/finalize", requireLoginApi, requireAdmin, (req, res) => {
  const { itemName } = req.body;
  if (!itemName) return res.status(400).json({ error: "itemName wajib." });

  if (isBidClosedByDeadline()) {
    return res.status(400).json({ error: "Deadline sudah lewat. Finalize berjalan otomatis." });
  }

  const item = db.prepare("SELECT * FROM items WHERE name=?").get(itemName);
  if (!item) return res.status(404).json({ error: "Item tidak ditemukan." });

  const already = db.prepare("SELECT 1 FROM finals WHERE item_id=?").get(item.id);
  if (already) return res.status(400).json({ error: "Item sudah finalized." });

  const hold = db.prepare("SELECT * FROM holds WHERE item_id=?").get(item.id);
  if (!hold) return res.status(400).json({ error: "Belum ada pemenang sementara untuk item ini." });

  const deadlineIso = getDeadlineIsoOrNull() || new Date().toISOString();

  const tx = db.transaction(() => {
    db.prepare("UPDATE items SET status='CLOSED' WHERE id=?").run(item.id);
    db.prepare("UPDATE members SET points_total = points_total - ? WHERE id=?").run(
      hold.amount,
      hold.member_id
    );
    db.prepare(`
      INSERT INTO finals(item_id, winner_member_id, amount, finalized_at)
      VALUES(?, ?, ?, ?)
    `).run(item.id, hold.member_id, hold.amount, deadlineIso);
    db.prepare("DELETE FROM holds WHERE item_id=?").run(item.id);
  });

  try { tx(); }
  catch (e) { return res.status(500).json({ error: "Gagal finalize.", detail: String(e.message || e) }); }

  res.json({ ok: true, message: "Finalize berhasil. Hasil tersimpan di tabel finals." });
});

app.get("/api/admin/bids", requireLoginApi, requireAdmin, (req, res) => {
  const { itemName, limit = 50 } = req.query;
  if (!itemName) return res.status(400).json({ error: "itemName wajib." });

  const item = db.prepare("SELECT * FROM items WHERE name=?").get(itemName);
  if (!item) return res.status(404).json({ error: "Item tidak ditemukan." });

  const rows = db
    .prepare(
      `
    SELECT b.created_at, m.nickname, b.amount
    FROM bids b
    JOIN members m ON m.id = b.member_id
    WHERE b.item_id = ?
    ORDER BY b.created_at DESC
    LIMIT ?
  `
    )
    .all(item.id, Math.min(parseInt(limit, 10) || 50, 200));

  res.json({ ok: true, item: item.name, bids: rows });
});

// ===================== (ADDED BACK) ADMIN: Import URLs + Import 1 klik =====================
app.get("/api/admin/import-urls", requireLoginApi, requireAdmin, (req, res) => {
  res.json({
    members_csv_url: getSetting("members_csv_url") || DEFAULT_MEMBERS_CSV_URL,
    items_csv_url: getSetting("items_csv_url") || DEFAULT_ITEMS_CSV_URL,
  });
});

app.post("/api/admin/set-import-urls", requireLoginApi, requireAdmin, (req, res) => {
  const { members_csv_url, items_csv_url } = req.body;
  if (typeof members_csv_url !== "string" || typeof items_csv_url !== "string") {
    return res.status(400).json({ error: "members_csv_url dan items_csv_url wajib string." });
  }
  setSetting("members_csv_url", members_csv_url.trim());
  setSetting("items_csv_url", items_csv_url.trim());
  res.json({ ok: true, message: "Import URLs tersimpan." });
});

// Import members robust + tidak menghapus data lama kalau parse=0
app.post("/api/admin/import-members", requireLoginApi, requireAdmin, async (req, res) => {
  const url = getSetting("members_csv_url") || DEFAULT_MEMBERS_CSV_URL;
  if (!url) return res.status(400).json({ error: "URL members CSV belum diset." });

  try {
    const csv = await fetchText(url);
    const rows = parseCsv(csv);
    if (rows.length < 2) return res.status(400).json({ error: "CSV members kosong / format salah." });

    const header = toHeaderMap(rows[0]);

    const parsed = [];
    for (let i = 1; i < rows.length; i++) {
      const r = rows[i];

      let nickname = pick(r, header, ["nickname", "nick", "name", "member", "nama"]);
      let ptsStr = pick(r, header, ["total point", "total_point", "points_total", "point", "points", "poin"]);

      if (!nickname) nickname = pickByIndex(r, 0, "");
      if (!ptsStr) ptsStr = pickByIndex(r, 1, "0");

      const low = (nickname || "").toLowerCase();
      if (!nickname) continue;
      if (low.includes("nickname") || low.includes("nick") || low.includes("member") || low.includes("nama")) continue;

      const pts = Math.max(0, parseInt(String(ptsStr).replace(/[^\d-]/g, ""), 10) || 0);
      parsed.push({ nickname: nickname.trim(), points_total: pts });
    }

    if (parsed.length === 0) {
      return res.status(400).json({
        error: "Import members gagal: tidak ada baris nickname yang terbaca. Cek header/kolom di sheet members.",
      });
    }

    const tx = db.transaction(() => {
      // reset bidding agar aman
      db.prepare("DELETE FROM holds").run();
      db.prepare("DELETE FROM bids").run();
      db.prepare("DELETE FROM finals").run();

      db.prepare("DELETE FROM members").run();

      const ins = db.prepare("INSERT INTO members(nickname, points_total) VALUES(?, ?)");
      for (const x of parsed) ins.run(x.nickname, x.points_total);
    });

    tx();
    res.json({ ok: true, message: "Import members berhasil (" + parsed.length + " rows) + reset bidding." });
  } catch (e) {
    res.status(500).json({ error: "Import members gagal.", detail: String(e.message || e) });
  }
});

app.post("/api/admin/import-items", requireLoginApi, requireAdmin, async (req, res) => {
  const url = getSetting("items_csv_url") || DEFAULT_ITEMS_CSV_URL;
  if (!url) return res.status(400).json({ error: "URL items CSV belum diset." });

  try {
    const csv = await fetchText(url);
    const rows = parseCsv(csv);
    if (rows.length < 2) return res.status(400).json({ error: "CSV items kosong / format salah." });

    const header = toHeaderMap(rows[0]);

    const parsed = [];
    for (let i = 1; i < rows.length; i++) {
      const r = rows[i];
      let name = pick(r, header, ["list item for bid", "item", "name", "nama", "items"]);
      if (!name) name = pickByIndex(r, 0, "");
      if (!name) continue;
      parsed.push(name.trim());
    }

    if (parsed.length === 0) return res.status(400).json({ error: "Import items gagal: tidak ada item yang terbaca." });

    const tx = db.transaction(() => {
      db.prepare("DELETE FROM holds").run();
      db.prepare("DELETE FROM bids").run();
      db.prepare("DELETE FROM finals").run();

      db.prepare("DELETE FROM items").run();

      const ins = db.prepare("INSERT INTO items(name, status) VALUES(?, 'OPEN')");
      for (const n of parsed) ins.run(n);
    });

    tx();
    res.json({ ok: true, message: "Import items berhasil (" + parsed.length + " rows) + reset bidding." });
  } catch (e) {
    res.status(500).json({ error: "Import items gagal.", detail: String(e.message || e) });
  }
});

// ===================== (ADDED BACK) ADMIN: Export CSV =====================
app.get("/api/admin/export-bids.csv", requireLoginApi, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT i.name AS item, m.nickname AS nickname, b.amount AS bid, b.created_at AS time_utc
    FROM bids b
    JOIN items i ON i.id = b.item_id
    JOIN members m ON m.id = b.member_id
    ORDER BY b.created_at ASC
  `).all();

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="bid_log.csv"');
  res.write("Item,Nickname,Bid,Time(UTC)\n");
  for (const r of rows) {
    res.write([r.item, r.nickname, r.bid, r.time_utc].map(csvEscape).join(",") + "\n");
  }
  res.end();
});

app.get("/api/admin/export-finals.csv", requireLoginApi, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT i.name AS item, m.nickname AS winner, f.amount AS bid, f.finalized_at AS time_utc
    FROM finals f
    JOIN items i ON i.id = f.item_id
    JOIN members m ON m.id = f.winner_member_id
    ORDER BY f.finalized_at ASC
  `).all();

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="final_results.csv"');
  res.write("Item,Winner,Bid,SettleTime(UTC)\n");
  for (const r of rows) {
    res.write([r.item, r.winner, r.bid, r.time_utc].map(csvEscape).join(",") + "\n");
  }
  res.end();
});

app.get("/api/admin/export-members.csv", requireLoginApi, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT m.nickname, m.points_total,
      COALESCE((SELECT SUM(h.amount) FROM holds h WHERE h.member_id=m.id),0) AS held_points
    FROM members m
    ORDER BY m.nickname ASC
  `).all();

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="members_snapshot.csv"');
  res.write("Nickname,TotalPoint,HeldPoint,Available\n");
  for (const r of rows) {
    const avail = (r.points_total || 0) - (r.held_points || 0);
    res.write([r.nickname, r.points_total, r.held_points, avail].map(csvEscape).join(",") + "\n");
  }
  res.end();
});

// ====================== Pages ======================
app.get("/login", (req, res) => {
  res.type("html").send(`
<!doctype html><html lang="id"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Login</title>
<style>
:root{--bg:#0b1020;--card:rgba(255,255,255,0.06);--border:rgba(255,255,255,0.14);--text:rgba(255,255,255,0.92);--muted:rgba(255,255,255,0.65);}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;background:
radial-gradient(1200px 600px at 15% 10%, rgba(124,58,237,0.25), transparent 60%),
radial-gradient(900px 500px at 85% 20%, rgba(34,197,94,0.18), transparent 60%),var(--bg);
font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;color:var(--text);}
.card{width:420px;max-width:100%;border:1px solid var(--border);background:var(--card);border-radius:18px;padding:16px;
box-shadow:0 18px 45px rgba(0,0,0,0.35);backdrop-filter:blur(10px);}
h2{margin:0 0 6px;font-size:18px}.muted{color:var(--muted);font-size:12px;margin-bottom:12px}
label{display:block;font-size:12px;color:var(--muted);margin:10px 0 6px}
select{width:100%;padding:11px 12px;border-radius:14px;border:1px solid rgba(255,255,255,0.14);background:rgba(255,255,255,0.06);color:var(--text);outline:none}
select option{background:#111827!important;color:#fff!important}
button{width:100%;margin-top:12px;padding:11px 14px;border-radius:14px;border:1px solid rgba(255,255,255,0.14);
background:linear-gradient(135deg, rgba(124,58,237,0.95), rgba(96,165,250,0.85));color:#fff;font-weight:900;cursor:pointer}
</style></head><body>
<div class="card">
<h2>Login Member</h2><div class="muted">Pilih nickname. Tidak pakai password.</div>
<label>Nickname</label><select id="member"></select>
<button onclick="login()">Masuk</button>
</div>
<script>
async function loadMembers(){
  const members = await fetch('/api/members').then(r=>r.json());
  document.getElementById('member').innerHTML = members.sort((a,b)=>a.nickname.localeCompare(b.nickname))
    .map(m => '<option value="'+m.nickname+'">'+m.nickname+'</option>').join('');
}
async function login(){
  const nickname = document.getElementById('member').value;
  const resp = await fetch('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({nickname})});
  const data = await resp.json();
  if(!resp.ok){alert(data.error||'Gagal login');return;}
  location.href='/';
}
loadMembers();
</script></body></html>
  `);
});

app.get("/", requireLogin, (req, res) => {
  res.type("html").send(`
<!doctype html>
<html lang="id"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ISEKAI Guild Bid</title>
<style>
:root{--bg:#0b1020;--card:rgba(255,255,255,0.06);--border:rgba(255,255,255,0.12);
--text:rgba(255,255,255,0.92);--muted:rgba(255,255,255,0.65);--shadow:0 12px 38px rgba(0,0,0,0.35);--radius:18px;}
*{box-sizing:border-box}
body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;color:var(--text);
background:
radial-gradient(1200px 600px at 15% 10%, rgba(124,58,237,0.25), transparent 60%),
radial-gradient(900px 500px at 85% 20%, rgba(34,197,94,0.18), transparent 60%),
radial-gradient(700px 350px at 70% 90%, rgba(59,130,246,0.14), transparent 55%),
var(--bg);min-height:100vh}
.container{max-width:980px;margin:0 auto;padding:26px 16px 36px}
.header{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.brand{display:flex;gap:12px;align-items:center}
.logo{width:44px;height:44px;border-radius:14px;background:linear-gradient(135deg, rgba(124,58,237,1), rgba(34,197,94,1));
box-shadow:0 10px 30px rgba(124,58,237,0.25);position:relative;overflow:hidden}
.logo:after{content:"";position:absolute;inset:-40%;background:radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), transparent 50%);transform:rotate(25deg)}
h1{margin:0;font-size:18px}.sub{margin:2px 0 0;color:var(--muted);font-size:12px}
.userbox{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid var(--border);background:rgba(255,255,255,0.04);border-radius:999px;font-size:12px;color:var(--muted)}
.userbox strong{color:var(--text)}
.btnPill{padding:8px 10px;border-radius:999px;border:1px solid rgba(255,255,255,0.14);background:rgba(255,255,255,0.06);color:var(--text);cursor:pointer;font-weight:900}
.adminBtn{border-color:rgba(245,158,11,0.35);background:rgba(245,158,11,0.14)}
.grid{display:grid;grid-template-columns:1fr;gap:14px}
@media (min-width:920px){.grid{grid-template-columns:420px 1fr}}
.card{border:1px solid var(--border);background:var(--card);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;backdrop-filter:blur(10px)}
.card-header{padding:16px 18px;border-bottom:1px solid rgba(255,255,255,0.08);display:flex;justify-content:space-between;align-items:flex-start;gap:10px}
.card-header h2{margin:0;font-size:14px;letter-spacing:0.25px;text-transform:uppercase;color:rgba(255,255,255,0.88)}
.card-header .desc{margin-top:5px;font-size:12px;color:var(--muted)}
.badge{display:inline-flex;padding:7px 10px;border-radius:999px;font-size:12px;white-space:nowrap;border:1px solid rgba(34,197,94,0.32);background:rgba(34,197,94,0.12);color:rgba(255,255,255,0.86);font-weight:900}
.badgeRed{border-color:rgba(239,68,68,0.42);background:rgba(239,68,68,0.18)}
.card-body{padding:16px 18px}
label{display:block;margin:10px 0 6px;font-size:12px;color:var(--muted)}
select,input{width:100%;padding:10px 10px;border-radius:14px;border:1px solid rgba(255,255,255,0.14);background:rgba(255,255,255,0.06);color:var(--text);outline:none}
select option{background:#111827!important;color:#fff!important}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.btn{width:100%;margin-top:10px;padding:10px 12px;border-radius:14px;border:1px solid rgba(255,255,255,0.14);background:linear-gradient(135deg, rgba(124,58,237,0.95), rgba(96,165,250,0.85));color:#fff;font-weight:900;cursor:pointer}
.btn-secondary{background:rgba(255,255,255,0.06);color:var(--text)}
.mini{font-size:12px;color:var(--muted);display:flex;justify-content:space-between;margin-top:10px;padding:10px 12px;border-radius:14px;border:1px solid rgba(255,255,255,0.09);background:rgba(255,255,255,0.04);gap:10px;flex-wrap:wrap}
.mini strong{color:rgba(255,255,255,0.9)}
.toast{margin-top:10px;padding:10px 12px;border-radius:14px;border:1px solid rgba(255,255,255,0.14);background:rgba(255,255,255,0.05);font-size:13px;line-height:1.35;display:none}
.toast.ok{display:block;border-color:rgba(34,197,94,0.35);background:rgba(34,197,94,0.12)}
.toast.err{display:block;border-color:rgba(239,68,68,0.35);background:rgba(239,68,68,0.12)}
.table-wrap{overflow:hidden;border-radius:16px;border:1px solid rgba(255,255,255,0.10);background:rgba(255,255,255,0.04)}
table{width:100%;border-collapse:collapse;table-layout:fixed}
thead th{font-size:11px;text-transform:uppercase;letter-spacing:0.25px;color:rgba(255,255,255,0.82);padding:10px 10px;text-align:left;background:rgba(255,255,255,0.06);border-bottom:1px solid rgba(255,255,255,0.10);white-space:nowrap}
tbody td{padding:10px 10px;font-size:12px;color:rgba(255,255,255,0.82);border-bottom:1px solid rgba(255,255,255,0.07);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.right{text-align:right}.divider{height:12px}.footer{margin-top:10px;font-size:12px;color:rgba(255,255,255,0.45);text-align:center}
.adminBox{margin-top:12px;padding:12px;border-radius:16px;border:1px solid rgba(245,158,11,0.22);background:rgba(245,158,11,0.08);display:none}
.adminTitle{font-weight:900;margin:0 0 10px;font-size:13px;color:rgba(255,255,255,0.9)}
.smallNote{font-size:12px;color:rgba(255,255,255,0.65);margin-top:6px}
.deadlineBar{display:none;padding:10px 12px;border-radius:16px;border:1px solid rgba(239,68,68,0.35);background: rgba(239,68,68,0.14);color: rgba(255,255,255,0.92);font-weight:900;margin: 0 0 14px}
.deadlineBar small{display:block;font-weight:700;color:rgba(255,255,255,0.75);margin-top:2px}
.madeby{margin-top: 10px;font-size: 12px;color: rgba(255,255,255,0.40);text-align: center;user-select:none} .madeby span{color: rgba(255,255,255,0.55)}

/* ===== minimize sections ===== */
.sectionHead{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:0 0 10px;cursor:pointer;user-select:none}
.sectionHead h3{margin:0;font-size:14px}
.chev{font-weight:900;color:rgba(255,255,255,0.7);border:1px solid rgba(255,255,255,0.14);background:rgba(255,255,255,0.06);border-radius:999px;padding:6px 10px;font-size:12px}
.sectionBody{display:block}
.sectionBody.min{display:none}
</style>
</head>
<body>
<div class="container">
  <div id="deadlineBar" class="deadlineBar"></div>

  <div class="header">
    <div class="brand">
      <div class="logo"></div>
      <div>
        <h1>ISEKAI Guild Bid System</h1>
        <div class="sub">· Auto hold/refund · Real-time dashboard ·</div>
      </div>
    </div>
    <div class="userbox">
      <span>Login:</span><strong id="who">...</strong>
      <button class="btnPill adminBtn" onclick="openAdmin()">Admin</button>
      <button class="btnPill" onclick="logout()">Logout</button>
    </div>
  </div>

  <div class="grid">
    <!-- LEFT -->
    <div class="card">
      <div class="card-header">
        <div>
          <h2>Place Bid</h2>
          <div class="desc">Pilih item lelang, lalu bid point.</div>
        </div>
        <span class="badge badgeRed" id="deadlineBadge">-</span>
      </div>
      <div class="card-body">
        <label>Item Lelang</label>
        <select id="item"></select>

        <div class="row">
          <div>
            <label>Bid Point</label>
            <input id="amount" type="number" min="1" value="1"/>
          </div>
          <div>
            <label>Quick</label>
            <select id="quick" onchange="quickSet()">
              <option value="1">+1</option>
              <option value="5">+5</option>
              <option value="10">+10</option>
              <option value="20">+20</option>
            </select>
          </div>
        </div>

        <button class="btn" id="bidBtn" onclick="placeBid()">Place Bid</button>
        <button class="btn btn-secondary" onclick="refreshAll()">Refresh</button>

        <div class="mini">
          <span>Poin tersedia:</span> <strong id="available">...</strong>
          <span>Highest saat ini:</span> <strong id="highest">...</strong>
        </div>

        <div class="toast" id="toast"></div>

        <!-- ADMIN LEFT -->
        <div id="adminLeft" class="adminBox">
          <div class="adminTitle">Admin: Kelola Member & Poin</div>

          <div class="row">
            <div>
              <label>Tambah Member (nickname)</label>
              <input id="newMember" placeholder="contoh: Budi"/>
            </div>
            <div>
              <label>Poin awal</label>
              <input id="newMemberPoints" type="number" min="0" value="0"/>
            </div>
          </div>
          <button class="btn" style="margin-top:10px;" onclick="addMember()">Tambah Member</button>

          <div class="divider"></div>

          <div class="row">
            <div>
              <label>Set Poin Member</label>
              <select id="adminMember"></select>
            </div>
            <div>
              <label>Total Poin</label>
              <input id="adminPoints" type="number" min="0" value="0"/>
            </div>
          </div>
          <button class="btn" style="margin-top:10px;" onclick="setPoints()">Simpan Poin</button>

          <div class="divider"></div>

          <label>Hapus Member</label>
          <div class="row">
            <div><select id="delMember"></select></div>
            <div><button class="btn btn-secondary" onclick="deleteMember()">Hapus</button></div>
          </div>
          <div class="smallNote">Catatan: tidak bisa hapus jika member pernah bid/hold/final.</div>
        </div>
      </div>
    </div>

    <!-- RIGHT -->
    <div class="card">
      <div class="card-header">
        <div>
          <h2>Dashboard</h2>
        </div>
        <span class="badge" id="lastUpdated">Loading...</span>
      </div>

      <div class="card-body">

        <!-- Member Points (minimize) -->
        <div class="sectionHead" onclick="toggleSection('secMembers')">
          <h3>Member Points</h3>
          <span class="chev" id="chev-secMembers">–</span>
        </div>
        <div class="sectionBody" id="secMembers">
          <div class="table-wrap">
            <table>
              <thead><tr>
                <th style="width:40%;">Nickname</th>
                <th class="right" style="width:20%;">Total</th>
                <th class="right" style="width:20%;">Held</th>
                <th class="right" style="width:20%;">Avail</th>
              </tr></thead>
              <tbody id="membersTbody"></tbody>
            </table>
          </div>
          <div class="divider"></div>
        </div>

        <!-- Items (minimize) -->
        <div class="sectionHead" onclick="toggleSection('secItems')">
          <h3>Items - Highest Bid</h3>
          <span class="chev" id="chev-secItems">–</span>
        </div>
        <div class="sectionBody" id="secItems">
          <div class="table-wrap">
            <table>
              <thead><tr>
                <th style="width:38%;">Item</th>
                <th style="width:16%;">Status</th>
                <th style="width:22%;">Highest</th>
                <th class="right" style="width:14%;">Bid</th>
                <th style="width:10%;">Time</th>
              </tr></thead>
              <tbody id="itemsTbody"></tbody>
            </table>
          </div>
          <div class="divider"></div>
        </div>

        <!-- Finals (minimize) -->
        <div class="sectionHead" onclick="toggleSection('secFinals')">
          <h3>Final Results (Winners)</h3>
          <span class="chev" id="chev-secFinals">–</span>
        </div>
        <div class="sectionBody" id="secFinals">
          <div class="table-wrap">
            <table>
              <thead><tr>
                <th style="width:42%;">Item</th>
                <th style="width:28%;">Winner</th>
                <th class="right" style="width:15%;">Bid</th>
                <th style="width:15%;">Time</th>
              </tr></thead>
              <tbody id="finalsTbody"></tbody>
            </table>
          </div>
        </div>

        <!-- ADMIN RIGHT -->
        <div id="adminRight" class="adminBox">
          <div class="adminTitle">Admin: Kelola Item + Finalize + Deadline</div>

          <div class="row">
            <div>
              <label>Tambah Item (nama)</label>
              <input id="newItem" placeholder="contoh: Mythic Bow"/>
            </div>
            <div>
              <label>&nbsp;</label>
              <button class="btn" onclick="addItem()">Tambah Item</button>
            </div>
          </div>

          <div class="divider"></div>

          <label>Hapus Item</label>
          <div class="row">
            <div><select id="delItem"></select></div>
            <div><button class="btn btn-secondary" onclick="deleteItem()">Hapus</button></div>
          </div>

          <div class="divider"></div>

          <label style="color:rgba(255,255,255,0.85);font-weight:900;">Hapus SEMUA Items</label>
          <button class="btn btn-secondary" onclick="deleteAllItems()">Delete ALL Items</button>
          <div class="smallNote">Menghapus: items + bids + holds + finals (member tetap ada).</div>

          <div class="divider"></div>

          <div class="row">
            <div>
              <label>Finalize Item (OPEN)</label>
              <select id="finalizeItem"></select>
            </div>
            <div>
              <label>&nbsp;</label>
              <button class="btn" onclick="finalizeSelected()">Finalize</button>
            </div>
          </div>

          <div class="divider"></div>

          <label>Log Bid (Item terpilih)</label>
          <div class="table-wrap">
            <table>
              <thead><tr>
                <th style="width:40%;">Waktu</th>
                <th style="width:40%;">Nickname</th>
                <th class="right" style="width:20%;">Bid</th>
              </tr></thead>
              <tbody id="logTbody"></tbody>
            </table>
          </div>

          <div class="divider"></div>

          <!-- ✅ DEADLINE AREA (1 input, seperti gambar) -->
          <label>Deadline Close Bid (WIB / UTC+7)</label>
          <div class="row">
            <div>
              <input id="deadlineLocal" type="datetime-local" />
              <div class="smallNote">Disimpan ke server sebagai ISO UTC (akhiran Z).</div>
            </div>
            <div>
              <button class="btn" onclick="saveDeadline()">Simpan</button>
            </div>
          </div>
          <button class="btn btn-secondary" style="margin-top:10px;" onclick="clearDeadline()">Clear Deadline</button>

          <!-- ===================== (ADDED BACK) IMPORT / EXPORT CSV MENU ===================== -->
          <div class="divider"></div>

          <div class="adminTitle">Admin: Import 1 Klik (Google Sheet CSV)</div>
          <div class="smallNote">Import akan replace all & reset bidding.</div>

          <div class="row" style="margin-top:8px;">
            <div>
              <label>Members CSV URL</label>
              <input id="membersCsvUrl" />
            </div>
            <div>
              <label>Items CSV URL</label>
              <input id="itemsCsvUrl" />
            </div>
          </div>

          <div class="row">
            <div><button class="btn" onclick="saveImportUrls()">Simpan URL</button></div>
            <div><button class="btn btn-secondary" onclick="loadImportUrls()">Load URL</button></div>
          </div>

          <div class="row" style="margin-top:8px;">
            <div><button class="btn" onclick="importMembers()">IMPORT MEMBERS</button></div>
            <div><button class="btn" onclick="importItems()">IMPORT ITEMS</button></div>
          </div>

          <div class="divider"></div>

          <div class="adminTitle">Admin: Export 1 Klik (CSV)</div>
          <div class="row" style="margin-top:8px;">
            <div><button class="btn btn-secondary" onclick="downloadCsv('/api/admin/export-bids.csv')">Export Bid Log</button></div>
            <div><button class="btn btn-secondary" onclick="downloadCsv('/api/admin/export-finals.csv')">Export Final Results</button></div>
          </div>
          <div class="row" style="margin-top:8px;">
            <div><button class="btn btn-secondary" onclick="downloadCsv('/api/admin/export-members.csv')">Export Members Snapshot</button></div>
            <div></div>
          </div>
          <!-- =============================================================================== -->

          <div class="divider"></div>
          <button class="btn btn-secondary" onclick="adminLogout()">Keluar Admin Mode</button>
        </div>

        <div class="footer">Auto refresh tabel setiap 10 detik.</div>
        <div class="madeby">Made by <span>᯽</span> @irfaaan_jo</div>
      </div>
    </div>
  </div>
</div>

<script>
let ME=null, DASH=null;

function toast(type, msg){
  const el = document.getElementById("toast");
  el.className = "toast " + (type === "ok" ? "ok" : "err");
  el.textContent = msg;
  setTimeout(function(){ el.className="toast"; el.textContent=""; }, 3200);
}

function pad2(n){ return String(n).padStart(2,'0'); }

// ===================== WIB FLAT HELPERS =====================
// Semua tampilan jam/refresh -> WIB (UTC+7) pakai getUTC* dengan offset manual
function timeNowUtc7(){
  const d = new Date(Date.now() + 7*3600*1000);
  return pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes()) + ":" + pad2(d.getUTCSeconds());
}

function toUtc7Display(utcIso){
  if(!utcIso) return "";
  const ms = Date.parse(utcIso);
  if(Number.isNaN(ms)) return "";
  const d = new Date(ms + 7*3600*1000);
  return pad2(d.getUTCDate()) + "/" + pad2(d.getUTCMonth()+1) + ", " + pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes());
}

function toUtc7InputValue(utcIso){
  // ISO UTC -> set ke datetime-local sebagai WIB (UTC+7)
  if(!utcIso) return "";
  const ms = Date.parse(utcIso);
  if(Number.isNaN(ms)) return "";
  const d = new Date(ms + 7*3600*1000);
  return d.getUTCFullYear() + "-" + pad2(d.getUTCMonth()+1) + "-" + pad2(d.getUTCDate()) + "T" + pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes());
}

function toUtcIsoFromUtc7LocalInput(localVal){
  // datetime-local value selalu "YYYY-MM-DDTHH:mm"
  // kita anggap itu WIB (UTC+7) -> ubah ke UTC ISO Z
  if(!localVal) return "";
  const parts = localVal.split("T");
  if(parts.length !== 2) return "";
  const ymd = parts[0].split("-").map(Number);
  const hm  = parts[1].split(":").map(Number);
  if(ymd.length !== 3 || hm.length < 2) return "";
  const y = ymd[0], m = ymd[1], d = ymd[2];
  const hh = hm[0], mm = hm[1];

  const utcMs = Date.UTC(y, m-1, d, hh-7, mm, 0, 0);
  const iso = new Date(utcMs).toISOString();
  if(Number.isNaN(Date.parse(iso))) return "";
  return iso;
}

function toUtc7HHMM(dt){
  if(!dt) return "-";
  var iso = dt.indexOf("T") >= 0 ? dt : (dt.replace(" ", "T") + "Z"); // sqlite -> iso
  var ms = Date.parse(iso);
  if(Number.isNaN(ms)) return "-";
  var d = new Date(ms + 7*3600*1000);
  return pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes());
}
// ===========================================================

// ===================== Minimize sections =====================
function toggleSection(id){
  const body = document.getElementById(id);
  const chev = document.getElementById("chev-"+id);
  const key = "min_"+id;

  const isMin = body.classList.toggle("min");
  chev.textContent = isMin ? "+" : "–";
  try{ localStorage.setItem(key, isMin ? "1" : "0"); }catch(e){}
}
function restoreSections(){
  ["secMembers","secItems","secFinals"].forEach(function(id){
    const key = "min_"+id;
    let v = "0";
    try{ v = localStorage.getItem(key) || "0"; }catch(e){}
    const body = document.getElementById(id);
    const chev = document.getElementById("chev-"+id);
    if(v === "1"){
      body.classList.add("min");
      chev.textContent = "+";
    }else{
      body.classList.remove("min");
      chev.textContent = "–";
    }
  });
}

async function loadMe(){
  const me = await fetch('/api/me').then(r=>r.json());
  if(!me.logged_in){ location.href='/login'; return null; }
  ME = me;

  document.getElementById("who").textContent = me.member.nickname;
  document.getElementById("available").textContent = me.member.available_points;

  const bar = document.getElementById("deadlineBar");
  const btn = document.getElementById("bidBtn");
  const badge = document.getElementById("deadlineBadge");

  if(me.bid_deadline_utc){
    badge.textContent = toUtc7Display(me.bid_deadline_utc);
  }else{
    badge.textContent = "-";
  }

  if(me.bid_deadline_utc){
    var deadlineTxt = toUtc7Display(me.bid_deadline_utc);
    bar.style.display = "block";
    if(me.bid_closed){
      bar.innerHTML = "BID CLOSED (Deadline lewat)<small>Deadline: " + deadlineTxt + " (UTC+7)</small>";
      btn.disabled = true; btn.style.opacity = 0.5; btn.style.cursor = "not-allowed";
    }else{
      bar.innerHTML = "Deadline Bid: " + deadlineTxt + " (UTC+7)<small>Jika lewat deadline, bid berhenti & auto-finalize.</small>";
      btn.disabled = false; btn.style.opacity = 1; btn.style.cursor = "pointer";
    }
  }else{
    bar.style.display = "none";
    btn.disabled = false; btn.style.opacity = 1; btn.style.cursor = "pointer";
  }

  document.getElementById("adminLeft").style.display = me.is_admin ? "block" : "none";
  document.getElementById("adminRight").style.display = me.is_admin ? "block" : "none";

  if(me.is_admin){
    document.getElementById("deadlineLocal").value = toUtc7InputValue(me.bid_deadline_utc || "");
  }
  return me;
}

async function loadOptions(){
  const items = await fetch('/api/items').then(r=>r.json());
  document.getElementById('item').innerHTML = items.filter(i=>i.status==='OPEN')
    .map(i=>'<option value="'+i.name+'">'+i.name+'</option>').join('');
}

function quickSet(){
  document.getElementById('amount').value = parseInt(document.getElementById('quick').value,10);
}

async function loadDashboard(tablesOnly){
  const data = await fetch('/api/dashboard').then(r=>r.json());
  DASH = data;

  document.getElementById("membersTbody").innerHTML = data.members.map(function(m){
    return '<tr>'
      + '<td title="'+m.nickname+'"><strong>'+m.nickname+'</strong></td>'
      + '<td class="right">'+m.points_total+'</td>'
      + '<td class="right">'+m.held_points+'</td>'
      + '<td class="right"><strong>'+m.available_points+'</strong></td>'
      + '</tr>';
  }).join("");

  document.getElementById("itemsTbody").innerHTML = data.items.map(function(i){
    var t = i.highest_time ? toUtc7HHMM(i.highest_time) : "-";
    return '<tr>'
      + '<td title="'+i.name+'"><strong>'+i.name+'</strong></td>'
      + '<td>'+i.status+'</td>'
      + '<td title="'+(i.highest_nickname || '-')+'">'+(i.highest_nickname || '-')+'</td>'
      + '<td class="right">'+(i.highest_amount || '-')+'</td>'
      + '<td>'+t+'</td>'
      + '</tr>';
  }).join("");

  var finals = (data.finals || []);
  document.getElementById("finalsTbody").innerHTML = finals.length ? finals.map(function(f){
    return '<tr>'
      + '<td title="'+f.item_name+'"><strong>'+f.item_name+'</strong></td>'
      + '<td title="'+f.winner+'">'+f.winner+'</td>'
      + '<td class="right"><strong>'+f.amount+'</strong></td>'
      + '<td title="'+f.finalized_at+'">'+toUtc7HHMM(f.finalized_at)+'</td>'
      + '</tr>';
  }).join("") : '<tr><td colspan="4">Belum ada finalize.</td></tr>';

  document.getElementById("lastUpdated").textContent = "Updated: " + timeNowUtc7();
  updateHighestForSelectedItem();

  if(!tablesOnly && ME && ME.is_admin){
    populateAdminDropdowns();
    await loadBidLog();
  }
}

function updateHighestForSelectedItem(){
  const itemName = document.getElementById('item').value;
  const found = DASH && DASH.items ? DASH.items.find(x=>x.name===itemName) : null;
  document.getElementById("highest").textContent =
    (found && found.highest_amount) ? (found.highest_amount + " (" + found.highest_nickname + ")") : "-";
}

async function refreshAll(){
  await loadMe();
  await loadOptions();
  await loadDashboard(false);
  toast("ok","Data berhasil direfresh.");
}

async function placeBid(){
  const itemName = document.getElementById('item').value;
  const amount = parseInt(document.getElementById('amount').value, 10);
  if(!itemName) return toast("err","Tidak ada item OPEN.");

  const resp = await fetch('/api/bid', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({itemName, amount})
  });
  const data = await resp.json();
  if(!resp.ok){ toast("err", data.error || "Gagal bid."); await refreshAll(); return; }
  toast("ok", data.message || "Bid diterima!");
  await refreshAll();
}

async function logout(){
  await fetch('/api/logout', {method:'POST'});
  location.href='/login';
}

// ---------- Admin ----------
async function openAdmin(){
  const pw = prompt("Masukkan password admin:");
  if(!pw) return;
  const resp = await fetch('/api/admin/login', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({password:pw})
  });
  const data = await resp.json();
  if(!resp.ok) return toast("err", data.error || "Gagal admin login.");
  toast("ok", data.message || "Admin aktif.");
  await loadImportUrls(); // ✅ load url import saat admin aktif
  await refreshAll();
}

async function adminLogout(){
  const resp = await fetch('/api/admin/logout', {method:'POST'});
  const data = await resp.json();
  toast("ok", data.message || "Admin off.");
  await refreshAll();
}

function populateAdminDropdowns(){
  const members = DASH && DASH.members ? DASH.members : [];
  const itemsAll = DASH && DASH.items ? DASH.items : [];
  const itemsOpen = itemsAll.filter(i=>i.status==="OPEN");

  const memOptions = members.map(m=>'<option value="'+m.nickname+'">'+m.nickname+'</option>').join("");
  document.getElementById("adminMember").innerHTML = memOptions;
  document.getElementById("delMember").innerHTML = memOptions;

  document.getElementById("finalizeItem").innerHTML = itemsOpen.map(i=>'<option value="'+i.name+'">'+i.name+'</option>').join("");
  document.getElementById("delItem").innerHTML = itemsAll.map(i=>'<option value="'+i.name+'">'+i.name+'</option>').join("");
}

async function loadBidLog(){
  const el = document.getElementById("finalizeItem");
  const tbody = document.getElementById("logTbody");
  if(!tbody) return;
  const itemName = el ? el.value : "";
  if(!itemName){ tbody.innerHTML = '<tr><td colspan="3">Pilih item OPEN untuk melihat log.</td></tr>'; return; }

  const resp = await fetch('/api/admin/bids?itemName='+encodeURIComponent(itemName));
  const data = await resp.json();
  if(!resp.ok){ tbody.innerHTML = '<tr><td colspan="3">Gagal memuat log.</td></tr>'; return; }

  tbody.innerHTML = (data.bids||[]).map(function(b){
    return '<tr><td title="'+b.created_at+'">'+b.created_at+'</td><td title="'+b.nickname+'"><strong>'+b.nickname+'</strong></td><td class="right">'+b.amount+'</td></tr>';
  }).join("") || '<tr><td colspan="3">Belum ada bid.</td></tr>';
}

async function addMember(){
  const nickname = document.getElementById("newMember").value.trim();
  const points_total = parseInt(document.getElementById("newMemberPoints").value,10);
  const resp = await fetch('/api/admin/add-member',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({nickname, points_total})
  });
  const data = await resp.json();
  if(!resp.ok) return toast("err", data.error || "Gagal tambah member.");
  toast("ok", data.message || "Member ditambah.");
  document.getElementById("newMember").value = "";
  await refreshAll();
}

async function deleteMember(){
  const nickname = document.getElementById("delMember").value;
  if(!confirm("Yakin hapus member: " + nickname + " ?")) return;
  const resp = await fetch('/api/admin/delete-member',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({nickname})
  });
  const data = await resp.json();
  if(!resp.ok) return toast("err", data.error || "Gagal hapus member.");
  toast("ok", data.message || "Member dihapus.");
  await refreshAll();
}

async function setPoints(){
  const nickname = document.getElementById("adminMember").value;
  const points_total = parseInt(document.getElementById("adminPoints").value,10);
  const resp = await fetch('/api/admin/set-points',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({nickname, points_total})
  });
  const data = await resp.json();
  if(!resp.ok) return toast("err", data.error || "Gagal set poin.");
  toast("ok", data.message || "Poin tersimpan.");
  await refreshAll();
}

async function addItem(){
  const name = document.getElementById("newItem").value.trim();
  const resp = await fetch('/api/admin/add-item',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name})
  });
  const data = await resp.json();
  if(!resp.ok) return toast("err", data.error || "Gagal tambah item.");
  toast("ok", data.message || "Item ditambah.");
  document.getElementById("newItem").value="";
  await refreshAll();
}

async function deleteItem(){
  const itemName = document.getElementById("delItem").value;
  if(!confirm("Yakin hapus item: " + itemName + " ?")) return;
  const resp = await fetch('/api/admin/delete-item',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({itemName})
  });
  const data = await resp.json();
  if(!resp.ok) return toast("err", data.error || "Gagal hapus item.");
  toast("ok", data.message || "Item dihapus.");
  await refreshAll();
}

async function deleteAllItems(){
  if(!confirm("INI AKAN MENGHAPUS SEMUA ITEMS + BIDS + HOLDS + FINALS. Lanjut?")) return;
  const resp = await fetch('/api/admin/delete-all-items?confirm=YES', {method:'POST'});
  const data = await resp.json();
  if(!resp.ok) return toast("err", data.error || "Gagal delete all items.");
  toast("ok", data.message || "Semua item dibersihkan.");
  await refreshAll();
}

async function finalizeSelected(){
  const itemName = document.getElementById("finalizeItem").value;
  if(!itemName) return toast("err","Tidak ada item OPEN untuk finalize.");
  const resp = await fetch('/api/admin/finalize',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({itemName})
  });
  const data = await resp.json();
  if(!resp.ok) return toast("err", data.error || "Gagal finalize.");
  toast("ok", data.message || "Finalize berhasil.");
  await refreshAll();
}

// ✅ Deadline: 1 input datetime-local (anggap WIB), simpan ISO Z (UTC)
async function saveDeadline(){
  const localVal = document.getElementById("deadlineLocal").value; // "YYYY-MM-DDTHH:mm"
  const deadline_utc = toUtcIsoFromUtc7LocalInput(localVal);
  if(!deadline_utc) return toast("err","Deadline belum diisi / format tidak valid.");
  const resp = await fetch('/api/admin/set-deadline',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({deadline_utc})
  });
  const data = await resp.json();
  if(!resp.ok) return toast("err", data.error || "Gagal simpan deadline.");
  toast("ok", data.message || "Deadline tersimpan.");
  await refreshAll();
}

async function clearDeadline(){
  const resp = await fetch('/api/admin/set-deadline',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({deadline_utc:""})
  });
  const data = await resp.json();
  if(!resp.ok) return toast("err", data.error || "Gagal clear deadline.");
  toast("ok", data.message || "Deadline dikosongkan.");
  await refreshAll();
}

document.addEventListener("change",function(e){
  if(e.target && e.target.id==="item") updateHighestForSelectedItem();
  if(e.target && e.target.id==="finalizeItem") loadBidLog();
});

// ===================== (ADDED BACK) Import/Export (Admin) =====================
async function loadImportUrls(){
  const r = await fetch('/api/admin/import-urls');
  const d = await r.json();
  if(!r.ok) return toast("err", d.error || "Gagal load URL");
  const a = document.getElementById("membersCsvUrl");
  const b = document.getElementById("itemsCsvUrl");
  if(a) a.value = d.members_csv_url || "";
  if(b) b.value = d.items_csv_url || "";
}

async function saveImportUrls(){
  const members_csv_url = (document.getElementById("membersCsvUrl").value || "").trim();
  const items_csv_url = (document.getElementById("itemsCsvUrl").value || "").trim();
  const r = await fetch('/api/admin/set-import-urls', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ members_csv_url, items_csv_url })
  });
  const d = await r.json();
  if(!r.ok) return toast("err", d.error || "Gagal simpan URL");
  toast("ok", d.message || "URL tersimpan");
}

async function importMembers(){
  if(!confirm("IMPORT MEMBERS akan REPLACE ALL + reset bidding. Lanjut?")) return;
  const r = await fetch('/api/admin/import-members', { method:'POST' });
  const d = await r.json();
  if(!r.ok) return toast("err", d.error || "Import members gagal");
  toast("ok", d.message || "Import members ok");
  await refreshAll();
}

async function importItems(){
  if(!confirm("IMPORT ITEMS akan REPLACE ALL + reset bidding. Lanjut?")) return;
  const r = await fetch('/api/admin/import-items', { method:'POST' });
  const d = await r.json();
  if(!r.ok) return toast("err", d.error || "Import items gagal");
  toast("ok", d.message || "Import items ok");
  await refreshAll();
}

function downloadCsv(url){
  const a = document.createElement('a');
  a.href = url; a.target = "_blank"; a.rel = "noopener";
  document.body.appendChild(a); a.click(); a.remove();
}
// ============================================================================

// boot
async function boot(){
  restoreSections();
  await loadMe();
  await loadOptions();
  await loadDashboard(false);

  setInterval(async function(){
    await loadMe();
    await loadDashboard(true); // tables only (admin input aman)
  }, 10000);
}
boot();
</script>
</body></html>
  `);
});

// ====================== Start server ======================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Running on port", PORT));

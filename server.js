/* ── Snippet Expander — Cloud Sync Backend ──────── */

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const initSqlJs = require("sql.js");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3456;

// Health check — registered early so it always responds
app.get("/health", (req, res) => res.json({ status: "ok" }));
const JWT_SECRET = process.env.JWT_SECRET || "snippet-expander-dev-secret-change-me";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data.db");

// Warn in production if using default secret
if (process.env.NODE_ENV === "production" && JWT_SECRET === "snippet-expander-dev-secret-change-me") {
  console.warn("⚠️  WARNING: Using default JWT_SECRET in production! Set JWT_SECRET env var.");
}

let db;

async function initDb() {
  const SQL = await initSqlJs();

  // Ensure the directory for DB_PATH exists
  const dbDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS snippets (
      id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      shortcut TEXT NOT NULL,
      html TEXT NOT NULL DEFAULT '',
      text_content TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      deleted INTEGER DEFAULT 0,
      PRIMARY KEY (id, user_id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // ── Team tables ────────────────────────────────
  db.run(`
    CREATE TABLE IF NOT EXISTS teams (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_id INTEGER NOT NULL,
      invite_code TEXT UNIQUE NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s','now') * 1000),
      FOREIGN KEY (owner_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS team_members (
      team_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      joined_at INTEGER DEFAULT (strftime('%s','now') * 1000),
      PRIMARY KEY (team_id, user_id),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS team_snippets (
      id TEXT NOT NULL,
      team_id TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      name TEXT NOT NULL,
      shortcut TEXT NOT NULL,
      html TEXT NOT NULL DEFAULT '',
      text_content TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      deleted INTEGER DEFAULT 0,
      PRIMARY KEY (id, team_id),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )
  `);

  // ── Folder tables ───────────────────────────────
  db.run(`
    CREATE TABLE IF NOT EXISTS folders (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s','now') * 1000),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS team_folders (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      name TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s','now') * 1000),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )
  `);

  // Add folder_id column to snippets if not present
  try { db.run("ALTER TABLE snippets ADD COLUMN folder_id TEXT DEFAULT NULL"); } catch {}
  try { db.run("ALTER TABLE team_snippets ADD COLUMN folder_id TEXT DEFAULT NULL"); } catch {}

  db.run(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      code TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (strftime('%s','now') * 1000),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  persist();
}

function persist() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function queryAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function queryOne(sql, params = []) {
  const rows = queryAll(sql, params);
  return rows[0] || null;
}

function generateInviteCode() {
  return crypto.randomBytes(4).toString("hex"); // 8-char code like "a3f9b2c1"
}

// ── Middleware ────────────────────────────────────
app.use(cors({
  origin: process.env.CORS_ORIGIN || "*",  // lock down in production if needed
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json({ limit: "5mb" }));

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ── Auth routes ──────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

  const existing = queryOne("SELECT id FROM users WHERE email = ?", [email]);
  if (existing) return res.status(409).json({ error: "Email already registered" });

  const hash = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (email, password_hash) VALUES (?, ?)", [email, hash]);
  persist();

  const user = queryOne("SELECT id FROM users WHERE email = ?", [email]);
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, email });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  const user = queryOne("SELECT * FROM users WHERE email = ?", [email]);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, email });
});

// ── Password reset routes ────────────────────────

// Request a password reset — sends a 6-digit code via email
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  console.log(`[forgot-password] Request for email: ${email}`);
  if (!email) return res.status(400).json({ error: "Email required" });

  const user = queryOne("SELECT id, email FROM users WHERE email = ?", [email]);
  if (!user) {
    console.log(`[forgot-password] No user found for: ${email}`);
    // Don't reveal whether the email exists
    return res.json({ ok: true, message: "If that email exists, a reset code has been sent." });
  }
  console.log(`[forgot-password] Found user ${user.id}, sending code...`);

  // Generate a 6-digit code, valid for 15 minutes
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 15 * 60 * 1000;

  // Invalidate any previous unused codes for this user
  db.run("UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0", [user.id]);

  // Store the new code
  db.run(
    "INSERT INTO password_reset_tokens (user_id, code, expires_at) VALUES (?, ?, ?)",
    [user.id, code, expiresAt]
  );
  persist();

  console.log(`Password reset code generated for ${user.email}`);

  // Return code directly (internal tool — no email needed)
  res.json({ ok: true, code, message: "Use this code to reset your password." });
});

// Verify code and set new password
app.post("/api/auth/reset-password", async (req, res) => {
  const { email, code, newPassword } = req.body;
  if (!email || !code || !newPassword) {
    return res.status(400).json({ error: "Email, code, and new password are required" });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  const user = queryOne("SELECT id FROM users WHERE email = ?", [email]);
  if (!user) return res.status(400).json({ error: "Invalid reset request" });

  const resetToken = queryOne(
    "SELECT * FROM password_reset_tokens WHERE user_id = ? AND code = ? AND used = 0 AND expires_at > ?",
    [user.id, code, Date.now()]
  );
  if (!resetToken) {
    return res.status(400).json({ error: "Invalid or expired reset code" });
  }

  // Mark the code as used
  db.run("UPDATE password_reset_tokens SET used = 1 WHERE id = ?", [resetToken.id]);

  // Update the password
  const hash = await bcrypt.hash(newPassword, 10);
  db.run("UPDATE users SET password_hash = ? WHERE id = ?", [hash, user.id]);
  persist();

  // Return a fresh auth token so they're logged in immediately
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ ok: true, token, email });
});

// ── Personal folder routes ──────────────────────

app.get("/api/folders", authMiddleware, (req, res) => {
  const rows = queryAll(
    "SELECT id, name, created_at AS createdAt FROM folders WHERE user_id = ?",
    [req.userId]
  );
  res.json(rows);
});

app.post("/api/folders", authMiddleware, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "Folder name required" });
  const id = crypto.randomUUID();
  db.run("INSERT INTO folders (id, user_id, name) VALUES (?, ?, ?)", [id, req.userId, name]);
  persist();
  res.json({ id, name });
});

app.put("/api/folders/:id", authMiddleware, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "Folder name required" });
  db.run("UPDATE folders SET name = ? WHERE id = ? AND user_id = ?", [name, req.params.id, req.userId]);
  persist();
  res.json({ ok: true });
});

app.delete("/api/folders/:id", authMiddleware, (req, res) => {
  // Unassign snippets from this folder first
  db.run("UPDATE snippets SET folder_id = NULL WHERE folder_id = ? AND user_id = ?", [req.params.id, req.userId]);
  db.run("DELETE FROM folders WHERE id = ? AND user_id = ?", [req.params.id, req.userId]);
  persist();
  res.json({ ok: true });
});

// ── Personal snippet routes ──────────────────────

app.get("/api/snippets", authMiddleware, (req, res) => {
  const rows = queryAll(
    "SELECT id, name, shortcut, html, text_content AS text, folder_id AS folderId, created_at AS createdAt, updated_at AS updatedAt FROM snippets WHERE user_id = ? AND deleted = 0",
    [req.userId]
  );
  res.json(rows);
});

app.put("/api/snippets", authMiddleware, (req, res) => {
  const { id, name, shortcut, html, text, folderId, createdAt, updatedAt } = req.body;
  if (!id || !name || !shortcut) return res.status(400).json({ error: "Missing fields" });

  const existing = queryOne("SELECT id FROM snippets WHERE id = ? AND user_id = ?", [id, req.userId]);

  if (existing) {
    db.run(
      "UPDATE snippets SET name = ?, shortcut = ?, html = ?, text_content = ?, folder_id = ?, updated_at = ?, deleted = 0 WHERE id = ? AND user_id = ?",
      [name, shortcut, html || "", text || "", folderId || null, updatedAt, id, req.userId]
    );
  } else {
    db.run(
      "INSERT INTO snippets (id, user_id, name, shortcut, html, text_content, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [id, req.userId, name, shortcut, html || "", text || "", folderId || null, createdAt, updatedAt]
    );
  }

  persist();
  res.json({ ok: true });
});

app.delete("/api/snippets/:id", authMiddleware, (req, res) => {
  db.run("UPDATE snippets SET deleted = 1, updated_at = ? WHERE id = ? AND user_id = ?",
    [Date.now(), req.params.id, req.userId]);
  persist();
  res.json({ ok: true });
});

app.post("/api/snippets/sync", authMiddleware, (req, res) => {
  const clientSnippets = req.body.snippets || [];
  const serverSnippets = queryAll(
    "SELECT id, name, shortcut, html, text_content AS text, folder_id AS folderId, created_at AS createdAt, updated_at AS updatedAt, deleted FROM snippets WHERE user_id = ?",
    [req.userId]
  );
  const serverMap = new Map(serverSnippets.map(s => [s.id, s]));

  for (const s of clientSnippets) {
    const server = serverMap.get(s.id);
    if (!server) {
      db.run(
        "INSERT INTO snippets (id, user_id, name, shortcut, html, text_content, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [s.id, req.userId, s.name, s.shortcut, s.html || "", s.text || "", s.folderId || null, s.createdAt, s.updatedAt]
      );
    } else if (s.updatedAt > server.updatedAt) {
      db.run(
        "UPDATE snippets SET name = ?, shortcut = ?, html = ?, text_content = ?, folder_id = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        [s.name, s.shortcut, s.html || "", s.text || "", s.folderId || null, s.updatedAt, s.id, req.userId]
      );
    }
  }

  persist();

  const merged = queryAll(
    "SELECT id, name, shortcut, html, text_content AS text, folder_id AS folderId, created_at AS createdAt, updated_at AS updatedAt FROM snippets WHERE user_id = ? AND deleted = 0",
    [req.userId]
  );
  res.json(merged);
});

// ── Team routes ──────────────────────────────────

// Create a new team
app.post("/api/teams", authMiddleware, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "Team name required" });

  const id = crypto.randomUUID();
  const inviteCode = generateInviteCode();

  db.run(
    "INSERT INTO teams (id, name, owner_id, invite_code) VALUES (?, ?, ?, ?)",
    [id, name, req.userId, inviteCode]
  );
  db.run(
    "INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, 'owner')",
    [id, req.userId]
  );
  persist();

  res.json({ id, name, inviteCode, role: "owner" });
});

// List teams the user belongs to
app.get("/api/teams", authMiddleware, (req, res) => {
  const teams = queryAll(`
    SELECT t.id, t.name, t.invite_code AS inviteCode, t.owner_id AS ownerId, tm.role
    FROM teams t
    JOIN team_members tm ON t.id = tm.team_id
    WHERE tm.user_id = ?
  `, [req.userId]);
  res.json(teams);
});

// Join a team by invite code
app.post("/api/teams/join", authMiddleware, (req, res) => {
  const { inviteCode } = req.body;
  if (!inviteCode) return res.status(400).json({ error: "Invite code required" });

  const team = queryOne("SELECT * FROM teams WHERE invite_code = ?", [inviteCode]);
  if (!team) return res.status(404).json({ error: "Invalid invite code" });

  const existing = queryOne(
    "SELECT * FROM team_members WHERE team_id = ? AND user_id = ?",
    [team.id, req.userId]
  );
  if (existing) return res.status(409).json({ error: "Already a member of this team" });

  db.run(
    "INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, 'member')",
    [team.id, req.userId]
  );
  persist();

  res.json({ id: team.id, name: team.name, inviteCode: team.invite_code, role: "member" });
});

// Leave a team
app.post("/api/teams/:teamId/leave", authMiddleware, (req, res) => {
  const { teamId } = req.params;
  const team = queryOne("SELECT * FROM teams WHERE id = ?", [teamId]);
  if (!team) return res.status(404).json({ error: "Team not found" });

  if (team.owner_id === req.userId) {
    return res.status(400).json({ error: "Owner cannot leave. Transfer ownership or delete the team." });
  }

  db.run("DELETE FROM team_members WHERE team_id = ? AND user_id = ?", [teamId, req.userId]);
  persist();
  res.json({ ok: true });
});

// Get team members
app.get("/api/teams/:teamId/members", authMiddleware, (req, res) => {
  const { teamId } = req.params;

  // Verify user is a member
  const membership = queryOne(
    "SELECT * FROM team_members WHERE team_id = ? AND user_id = ?",
    [teamId, req.userId]
  );
  if (!membership) return res.status(403).json({ error: "Not a team member" });

  const members = queryAll(`
    SELECT u.id, u.email, tm.role, tm.joined_at AS joinedAt
    FROM team_members tm
    JOIN users u ON tm.user_id = u.id
    WHERE tm.team_id = ?
  `, [teamId]);
  res.json(members);
});

// ── Team folder routes ──────────────────────────

app.get("/api/teams/:teamId/folders", authMiddleware, (req, res) => {
  const { teamId } = req.params;
  const membership = queryOne("SELECT * FROM team_members WHERE team_id = ? AND user_id = ?", [teamId, req.userId]);
  if (!membership) return res.status(403).json({ error: "Not a team member" });

  const rows = queryAll(
    "SELECT id, name, created_at AS createdAt FROM team_folders WHERE team_id = ?",
    [teamId]
  );
  res.json(rows);
});

app.post("/api/teams/:teamId/folders", authMiddleware, (req, res) => {
  const { teamId } = req.params;
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "Folder name required" });

  const membership = queryOne("SELECT * FROM team_members WHERE team_id = ? AND user_id = ?", [teamId, req.userId]);
  if (!membership) return res.status(403).json({ error: "Not a team member" });

  const id = crypto.randomUUID();
  db.run("INSERT INTO team_folders (id, team_id, name, created_by) VALUES (?, ?, ?, ?)", [id, teamId, name, req.userId]);
  persist();
  res.json({ id, name });
});

app.put("/api/teams/:teamId/folders/:folderId", authMiddleware, (req, res) => {
  const { teamId, folderId } = req.params;
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "Folder name required" });

  const membership = queryOne("SELECT * FROM team_members WHERE team_id = ? AND user_id = ?", [teamId, req.userId]);
  if (!membership) return res.status(403).json({ error: "Not a team member" });

  db.run("UPDATE team_folders SET name = ? WHERE id = ? AND team_id = ?", [name, folderId, teamId]);
  persist();
  res.json({ ok: true });
});

app.delete("/api/teams/:teamId/folders/:folderId", authMiddleware, (req, res) => {
  const { teamId, folderId } = req.params;
  const membership = queryOne("SELECT * FROM team_members WHERE team_id = ? AND user_id = ?", [teamId, req.userId]);
  if (!membership) return res.status(403).json({ error: "Not a team member" });

  db.run("UPDATE team_snippets SET folder_id = NULL WHERE folder_id = ? AND team_id = ?", [folderId, teamId]);
  db.run("DELETE FROM team_folders WHERE id = ? AND team_id = ?", [folderId, teamId]);
  persist();
  res.json({ ok: true });
});

// ── Team snippet routes ──────────────────────────

// Get all team snippets
app.get("/api/teams/:teamId/snippets", authMiddleware, (req, res) => {
  const { teamId } = req.params;

  const membership = queryOne(
    "SELECT * FROM team_members WHERE team_id = ? AND user_id = ?",
    [teamId, req.userId]
  );
  if (!membership) return res.status(403).json({ error: "Not a team member" });

  const rows = queryAll(`
    SELECT ts.id, ts.name, ts.shortcut, ts.html, ts.text_content AS text,
           ts.folder_id AS folderId,
           ts.created_at AS createdAt, ts.updated_at AS updatedAt,
           u.email AS createdByEmail
    FROM team_snippets ts
    JOIN users u ON ts.created_by = u.id
    WHERE ts.team_id = ? AND ts.deleted = 0
  `, [teamId]);
  res.json(rows);
});

// Create / update a team snippet
app.put("/api/teams/:teamId/snippets", authMiddleware, (req, res) => {
  const { teamId } = req.params;
  const { id, name, shortcut, html, text, folderId, createdAt, updatedAt } = req.body;
  if (!id || !name || !shortcut) return res.status(400).json({ error: "Missing fields" });

  const membership = queryOne(
    "SELECT * FROM team_members WHERE team_id = ? AND user_id = ?",
    [teamId, req.userId]
  );
  if (!membership) return res.status(403).json({ error: "Not a team member" });

  const existing = queryOne("SELECT id FROM team_snippets WHERE id = ? AND team_id = ?", [id, teamId]);

  if (existing) {
    db.run(
      "UPDATE team_snippets SET name = ?, shortcut = ?, html = ?, text_content = ?, folder_id = ?, updated_at = ?, deleted = 0 WHERE id = ? AND team_id = ?",
      [name, shortcut, html || "", text || "", folderId || null, updatedAt, id, teamId]
    );
  } else {
    db.run(
      "INSERT INTO team_snippets (id, team_id, created_by, name, shortcut, html, text_content, folder_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [id, teamId, req.userId, name, shortcut, html || "", text || "", folderId || null, createdAt, updatedAt]
    );
  }

  persist();
  res.json({ ok: true });
});

// Delete a team snippet
app.delete("/api/teams/:teamId/snippets/:id", authMiddleware, (req, res) => {
  const { teamId, id } = req.params;

  const membership = queryOne(
    "SELECT * FROM team_members WHERE team_id = ? AND user_id = ?",
    [teamId, req.userId]
  );
  if (!membership) return res.status(403).json({ error: "Not a team member" });

  db.run("UPDATE team_snippets SET deleted = 1, updated_at = ? WHERE id = ? AND team_id = ?",
    [Date.now(), id, teamId]);
  persist();
  res.json({ ok: true });
});

// ── Start ────────────────────────────────────────
console.log(`Starting server... PORT=${PORT}, DB_PATH=${DB_PATH}`);
initDb().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Snippet Expander backend running on port ${PORT}`);
  });
}).catch((err) => {
  console.error("Failed to initialize:", err);
  process.exit(1);
});

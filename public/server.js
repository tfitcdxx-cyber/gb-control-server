const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { authenticator } = require("otplib");
const QRCode = require("qrcode");

const app = express();
const PORT = process.env.PORT || 4000;

const ROOT_KEY = process.env.ADMIN_TOKEN || "changeme123";

const ALL_MODULES = [
  "ADB-Management", "Auto-Approve", "Auto-Reject", "BBL-Auto",
  "KPI-Dashboard", "Member", "Payment Management", "STM-Check",
  "Settlement-Account", "Telegram-Alert", "transfer-Confirm",
  "GB777",
];

const RISKY_MODULES = [
  "Payment Management", "Settlement-Account", "transfer-Confirm",
  "BBL-Auto", "ADB-Management",
];

const STATE_FILE = path.join(__dirname, "control-state.json");
const USERS_FILE = path.join(__dirname, "users.json");

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const UPDATES_DIR = path.join(__dirname, "updates");
if (!fs.existsSync(UPDATES_DIR)) fs.mkdirSync(UPDATES_DIR, { recursive: true });
app.use("/updates", express.static(UPDATES_DIR));

function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    return fallback;
  }
}

function saveJson(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error("[Control Server] save failed:", file, err.message);
  }
}

let machines = new Map(Object.entries(loadJson(STATE_FILE, {})));
function saveMachines() {
  saveJson(STATE_FILE, Object.fromEntries(machines));
}

const machineLogs = new Map(); // machineId -> string[]
const MAX_LOG_LINES = 500;

function requireFreshTotp(req, res, session) {
  const u = users[session.username];
  const totp = req.body && req.body.totp;
  if (!u || !authenticator.check(String(totp || ""), u.totpSecret)) {
    res.status(401).json({ error: "step-up 2FA required", requireTotp: true });
    return false;
  }
  return true;
}

let users = loadJson(USERS_FILE, {});
function saveUsers() {
  saveJson(USERS_FILE, users);
}

const sessions = new Map();
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

function newSession(username) {
  const token = crypto.randomBytes(24).toString("hex");
  const u = users[username];
  sessions.set(token, {
    username,
    role: u.role,
    allowedModules: u.allowedModules,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  return token;
}

function getSession(req) {
  const token = req.headers["x-session-token"];
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return s;
}

function canSeeModule(session, moduleName) {
  if (session.role === "superadmin") return true;
  if (!Array.isArray(session.allowedModules)) return false;
  return session.allowedModules.includes("*") || session.allowedModules.includes(moduleName);
}

function requireRoot(req, res, next) {
  if (req.headers["x-admin-token"] !== ROOT_KEY) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

function requireUser(req, res, next) {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: "not logged in" });
  req.session = session;
  next();
}

// ---------- root key: manage users ----------
app.get("/api/admin/modules", requireRoot, (req, res) => {
  res.json({ all: ALL_MODULES, risky: RISKY_MODULES });
});

app.get("/api/admin/users", requireRoot, (req, res) => {
  const list = Object.entries(users).map(([username, u]) => ({
    username,
    role: u.role,
    allowedModules: u.allowedModules,
    enabled: u.enabled !== false,
  }));
  res.json({ users: list });
});

app.post("/api/admin/users", requireRoot, async (req, res) => {
  const { username, password, role, allowedModules } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "missing username or password" });
  }
  if (users[username]) return res.status(409).json({ error: "user already exists" });

  const secret = authenticator.generateSecret();
  users[username] = {
    passwordHash: bcrypt.hashSync(password, 10),
    totpSecret: secret,
    role: role === "superadmin" ? "superadmin" : "user",
    allowedModules: role === "superadmin" ? ["*"] : (Array.isArray(allowedModules) ? allowedModules : []),
    enabled: true,
  };
  saveUsers();

  const otpauth = authenticator.keyuri(username, "GB Control", secret);
  const qrDataUrl = await QRCode.toDataURL(otpauth);
  res.json({ success: true, username, otpauth, qrDataUrl });
});

app.patch("/api/admin/users/:username", requireRoot, (req, res) => {
  const u = users[req.params.username];
  if (!u) return res.status(404).json({ error: "not found" });
  const { role, allowedModules, enabled } = req.body || {};
  if (role === "superadmin" || role === "user") u.role = role;
  if (Array.isArray(allowedModules)) u.allowedModules = u.role === "superadmin" ? ["*"] : allowedModules;
  if (typeof enabled === "boolean") u.enabled = enabled;
  saveUsers();
  res.json({ success: true });
});

app.delete("/api/admin/users/:username", requireRoot, (req, res) => {
  delete users[req.params.username];
  saveUsers();
  res.json({ success: true });
});

// ---------- login (password + TOTP) ----------
app.post("/api/login", (req, res) => {
  const { username, password, totp } = req.body || {};
  const u = users[username];
  if (!u || u.enabled === false) return res.status(401).json({ error: "invalid credentials" });
  if (!bcrypt.compareSync(password || "", u.passwordHash)) {
    return res.status(401).json({ error: "invalid credentials" });
  }
  if (!authenticator.check(String(totp || ""), u.totpSecret)) {
    return res.status(401).json({ error: "invalid 2FA code" });
  }
  const token = newSession(username);
  res.json({ token, role: u.role, allowedModules: u.allowedModules });
});

// ---------- client machines report in ----------
app.post("/api/heartbeat", (req, res) => {
  const {
    machineId, name, project,
    enabled, running, hasToken,
    lastCheckAt, processedCount, lastError,
    publicIp, backendUser,
  } = req.body || {};

  if (!machineId) return res.status(400).json({ error: "missing machineId" });

  const existing = machines.get(machineId) || {};
  const updated = {
    ...existing,
    machineId,
    name: name || existing.name || machineId,
    project: project || existing.project || "-",
    enabled: !!enabled,
    running: !!running,
    hasToken: !!hasToken,
    publicIp: publicIp || existing.publicIp || null,
    backendUser: backendUser || existing.backendUser || null,
    lastCheckAt: lastCheckAt || null,
    processedCount: processedCount || 0,
    lastError: lastError || null,
    lastSeenAt: new Date().toISOString(),
    desiredEnabled: existing.desiredEnabled === undefined ? null : existing.desiredEnabled,
    pendingTask: existing.pendingTask || null,
    lastTaskResult: existing.lastTaskResult || null,
  };
  machines.set(machineId, updated);
  saveMachines();

  res.json({ desiredEnabled: updated.desiredEnabled, task: updated.pendingTask || null });
});

// ---------- client machines report ผลลัพธ์ของงานที่สั่งไป ----------
app.post("/api/task-result", (req, res) => {
  const { machineId, taskId, success, result, error } = req.body || {};
  const m = machines.get(machineId);
  if (!m) return res.status(404).json({ error: "not found" });
  if (m.pendingTask && m.pendingTask.id === taskId) {
    m.lastTaskResult = {
      taskId,
      type: m.pendingTask.type,
      success: !!success,
      result: result || null,
      error: error || null,
      finishedAt: new Date().toISOString(),
    };
    m.pendingTask = null;
    machines.set(machineId, m);
    saveMachines();
  }
  res.json({ success: true });
});

// ---------- client machines ส่ง log บรรทัดใหม่เข้ามา ----------
app.post("/api/logs", (req, res) => {
  const { machineId, lines } = req.body || {};
  if (!machineId || !Array.isArray(lines)) return res.status(400).json({ error: "missing data" });
  const existing = machineLogs.get(machineId) || [];
  const updatedLogs = existing.concat(lines);
  machineLogs.set(machineId, updatedLogs.slice(-MAX_LOG_LINES));
  res.json({ success: true });
});

// ---------- logged-in users: view/control machines within their allowed modules ----------
app.get("/api/machines", requireUser, (req, res) => {
  const list = Array.from(machines.values()).filter((m) => canSeeModule(req.session, m.project));
  res.json({ machines: list, allowedModules: req.session.allowedModules, role: req.session.role });
});

app.post("/api/machines/:id/command", requireUser, (req, res) => {
  const m = machines.get(req.params.id);
  if (!m) return res.status(404).json({ error: "not found" });
  if (!canSeeModule(req.session, m.project)) return res.status(403).json({ error: "no access to this module" });

  if (RISKY_MODULES.includes(m.project)) {
    const u = users[req.session.username];
    const totp = req.body && req.body.totp;
    if (!u || !authenticator.check(String(totp || ""), u.totpSecret)) {
      return res.status(401).json({ error: "step-up 2FA required", requireTotp: true });
    }
  }

  m.desiredEnabled = req.body.enabled === null ? null : !!req.body.enabled;
  machines.set(req.params.id, m);
  saveMachines();
  res.json({ success: true, machine: m });
});

app.get("/api/machines/:id/logs", requireUser, (req, res) => {
  const m = machines.get(req.params.id);
  if (!m) return res.status(404).json({ error: "not found" });
  if (!canSeeModule(req.session, m.project)) return res.status(403).json({ error: "no access to this module" });
  res.json({ lines: machineLogs.get(req.params.id) || [] });
});

// ---------- สั่งงานระยะไกล: แก้ไฟล์ / git / config — ถือเป็นคำสั่งเสี่ยงเสมอ ต้องยืนยัน 2FA ทุกครั้ง ----------
app.post("/api/machines/:id/task", requireUser, (req, res) => {
  const m = machines.get(req.params.id);
  if (!m) return res.status(404).json({ error: "not found" });
  if (!canSeeModule(req.session, m.project)) return res.status(403).json({ error: "no access to this module" });
  if (!requireFreshTotp(req, res, req.session)) return;

  const { type, payload } = req.body || {};
  const ALLOWED_TASKS = ["readFile", "writeFile", "listDir", "gitStatus", "gitPull", "gitLog", "getConfig", "setConfig"];
  if (!ALLOWED_TASKS.includes(type)) return res.status(400).json({ error: "unknown task type" });

  m.pendingTask = {
    id: crypto.randomBytes(8).toString("hex"),
    type,
    payload: payload || {},
    requestedBy: req.session.username,
    requestedAt: new Date().toISOString(),
  };
  m.lastTaskResult = null;
  machines.set(req.params.id, m);
  saveMachines();
  res.json({ success: true, taskId: m.pendingTask.id });
});

app.get("/api/machines/:id/task-result", requireUser, (req, res) => {
  const m = machines.get(req.params.id);
  if (!m) return res.status(404).json({ error: "not found" });
  if (!canSeeModule(req.session, m.project)) return res.status(403).json({ error: "no access to this module" });
  res.json({ pendingTask: m.pendingTask || null, lastTaskResult: m.lastTaskResult || null });
});

app.delete("/api/machines/:id", requireUser, (req, res) => {
  const m = machines.get(req.params.id);
  if (!m) return res.status(404).json({ error: "not found" });
  if (!canSeeModule(req.session, m.project)) return res.status(403).json({ error: "no access to this module" });
  machines.delete(req.params.id);
  saveMachines();
  res.json({ success: true });
});

app.listen(PORT, () => console.log(`[Control Server] running on port ${PORT}`));

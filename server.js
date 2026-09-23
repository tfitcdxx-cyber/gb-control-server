const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 4000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "changeme123";

const STATE_FILE = path.join(__dirname, "control-state.json");

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function loadMachines() {
  try {
    const raw = fs.readFileSync(STATE_FILE, "utf8");
    return new Map(Object.entries(JSON.parse(raw)));
  } catch (err) {
    return new Map();
  }
}

function saveMachines() {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(Object.fromEntries(machines), null, 2));
  } catch (err) {
    console.error("[Control Server] save failed:", err.message);
  }
}

const machines = loadMachines();

app.post("/api/heartbeat", (req, res) => {
  const {
    machineId, name, project,
    enabled, running, hasToken,
    lastCheckAt, processedCount, lastError,
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
    lastCheckAt: lastCheckAt || null,
    processedCount: processedCount || 0,
    lastError: lastError || null,
    lastSeenAt: new Date().toISOString(),
    desiredEnabled: existing.desiredEnabled === undefined ? null : existing.desiredEnabled,
  };
  machines.set(machineId, updated);
  saveMachines();

  res.json({ desiredEnabled: updated.desiredEnabled });
});

function requireAdmin(req, res, next) {
  if (req.headers["x-admin-token"] !== ADMIN_TOKEN) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

app.get("/api/machines", requireAdmin, (req, res) => {
  res.json({ machines: Array.from(machines.values()) });
});

app.post("/api/machines/:id/command", requireAdmin, (req, res) => {
  const m = machines.get(req.params.id);
  if (!m) return res.status(404).json({ error: "not found" });
  m.desiredEnabled = req.body.enabled === null ? null : !!req.body.enabled;
  machines.set(req.params.id, m);
  saveMachines();
  res.json({ success: true, machine: m });
});

app.delete("/api/machines/:id", requireAdmin, (req, res) => {
  machines.delete(req.params.id);
  saveMachines();
  res.json({ success: true });
});

app.listen(PORT, () => console.log(`[Control Server] running on port ${PORT}`));

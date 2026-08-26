import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import fs from "node:fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// In-memory store of visits. On Railway each instance keeps its own copy,
// but cross-tab/cross-session comparison within one instance works fine.
// Persist to a JSON file so restarts don't lose history.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, ".data");
const VISITS_FILE = path.join(DATA_DIR, "visits.json");
fs.mkdirSync(DATA_DIR, { recursive: true });

function loadVisits() {
  try {
    return JSON.parse(fs.readFileSync(VISITS_FILE, "utf8"));
  } catch {
    return [];
  }
}

function saveVisits(visits) {
  fs.writeFileSync(VISITS_FILE, JSON.stringify(visits, null, 2));
}

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

function hashId(id) {
  return crypto.createHash("sha256").update(String(id)).digest("hex").slice(0, 16);
}

// POST /api/visits  { fingerprint, signals, meta }
app.post("/api/visits", (req, res) => {
  const { fingerprint, signals, meta } = req.body || {};
  if (!fingerprint || typeof fingerprint !== "string") {
    return res.status(400).json({ error: "fingerprint is required" });
  }
  const visits = loadVisits();
  const visit = {
    id: hashId(crypto.randomUUID()),
    fingerprint,
    signals: signals || null,
    meta: meta || {},
    ts: Date.now()
  };
  visits.push(visit);
  saveVisits(visits);
  res.json({ id: visit.id });
});

// GET /api/visits  -> recent visits with their fingerprints
app.get("/api/visits", (req, res) => {
  const visits = loadVisits();
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
  res.json(visits.slice(-limit).reverse());
});

// GET /api/compare?self=<fp> -> which stored fingerprints match yours
app.get("/api/compare", (req, res) => {
  const self = req.query.self;
  if (!self || typeof self !== "string") {
    return res.status(400).json({ error: "self fingerprint required" });
  }
  const visits = loadVisits();
  const matches = visits.filter((v) => v.fingerprint === self);
  const total = visits.length;
  res.json({ self, matches: matches.length, total, visits: matches.slice(-20).reverse() });
});

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Fingerprint Inspector running at http://localhost:${PORT}`);
});

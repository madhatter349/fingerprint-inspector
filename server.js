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

// Advertise high-entropy client hints so Chrome actually sends them.
// Real trackers do this; without it we'd only see low-entropy hints.
// Must run BEFORE express.static so static files get the header too.
app.use((req, res, next) => {
  res.setHeader(
    "Accept-CH",
    "sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-ch-ua-platform-version, sec-ch-ua-full-version-list, sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-model, sec-ch-ua-wow64, sec-ch-ua-full-version, sec-ch-prefers-color-scheme, sec-ch-prefers-reduced-motion, sec-ch-viewport-height, sec-ch-viewport-width, sec-ch-dpr, sec-ch-device-memory, sec-ch-downlink, sec-ch-ect, sec-ch-rtt"
  );
  next();
});

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

// GET /api/whoami -> everything the server can see about the visitor, no consent needed.
// This is the "network identity" half of tracking: IP, client hints, headers.
const HINT_HEADERS = [
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-ch-ua-platform-version",
  "sec-ch-ua-full-version-list",
  "sec-ch-ua-arch",
  "sec-ch-ua-bitness",
  "sec-ch-ua-model",
  "sec-ch-ua-wow64",
  "sec-ch-prefers-color-scheme",
  "sec-ch-prefers-reduced-motion",
  "sec-ch-prefers-reduced-transparency",
  "sec-ch-viewport-height",
  "sec-ch-viewport-width",
  "sec-ch-dpr",
  "sec-ch-device-memory",
  "sec-ch-downlink",
  "sec-ch-ect",
  "sec-ch-rtt"
];

app.get("/api/whoami", (req, res) => {
  const hints = {};
  for (const h of HINT_HEADERS) {
    if (req.headers[h]) hints[h] = req.headers[h];
  }

  const forwarded = req.headers["x-forwarded-for"] || req.ip || "";
  const ip = forwarded.split(",")[0].trim() || "unknown";

  const out = {
    ip,
    ipNote: "IP is visible to every site you visit — no permission needed. Combined with the ASN/ISP and metro it is a coarse location that persists even in incognito.",
    clientHints: hints,
    clientHintsNote: "High-entropy client hints are sent to every server automatically. Together they encode CPU arch, bitness, platform version, memory, and screen — major fingerprint entropy.",
    headers: {
      accept_language: req.headers["accept-language"] || null,
      accept: (req.headers.accept || "").slice(0, 200),
      referer: req.headers.referer || null,
      dnt: req.headers.dnt || null,
      sec_fetch_site: req.headers["sec-fetch-site"] || null,
      sec_fetch_dest: req.headers["sec-fetch-dest"] || null
    },
    tls: req.socket.encrypted ? "TLS" : "plain",
    ts: Date.now()
  };

  // Optional geo enrichment if IPINFO_TOKEN is set (Railway secret). Without it,
  // we still report the raw IP and its subnet grouping.
  if (process.env.IPINFO_TOKEN) {
    fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${process.env.IPINFO_TOKEN}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("geo status " + r.status))))
      .then((geo) => {
        out.geo = {
          org: geo.org,
          asn: geo.asn && geo.asn.asn,
          city: geo.city,
          region: geo.region,
          country: geo.country,
          postal: geo.postal,
          timezone: geo.timezone
        };
        res.json(out);
      })
      .catch((e) => {
        out.geo = { note: "geo lookup failed: " + e.message };
        res.json(out);
      });
  } else {
    // Hash the IP into a coarse /16 grouping so the raw address isn't logged.
    const parts = ip.split(".").slice(0, 2).join(".");
    out.ipCoarse = parts + ".x.x";
    res.json(out);
  }
});

app.listen(PORT, () => {
  console.log(`Fingerprint Inspector running at http://localhost:${PORT}`);
});

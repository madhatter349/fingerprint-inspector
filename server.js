import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import fs from "node:fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Disable Express's auto ETag so our custom supercookie ETag isn't overridden.
app.disable("etag");

// Minimal cookie parser (avoids a dependency).
function getCookie(req, name) {
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    if (key === name) return decodeURIComponent(part.slice(idx + 1).trim());
  }
  return null;
}
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

// ---------------------------------------------------------------------------
// TRACKING LAB — the actual mechanisms sites use to identify visitors.
// Everything here is first-party (this site's own cookies/storage), which is
// exactly how every site tracks its visitors. Third-party cookies are blocked,
// but first-party mechanisms work everywhere.
// ---------------------------------------------------------------------------

// 1. First-party visitor cookie: the baseline mechanism.
//    Sets __fp_vid (6 months) and __fp_session (session-only). Real sites do
//    this with their own ID. Works even when third-party cookies are blocked.
app.get("/api/lab/cookie", (req, res) => {
  let vid = getCookie(req, "__fp_vid") || null;
  const isNew = !vid;
  if (!vid) {
    vid = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
  }
  res.setHeader("Set-Cookie", [
    `__fp_vid=${vid}; Path=/; Max-Age=${60 * 60 * 24 * 180}; SameSite=Lax`,
    `__fp_session=${crypto.randomUUID().slice(0, 8)}; Path=/; HttpOnly; SameSite=Lax`
  ]);
  res.json({ vid, isNew, note: "First-party cookie set by every site. Survives tab close; cleared by 'clear cookies' or incognito." });
});

// 2. ETag supercookie: an ID stored in the browser HTTP cache (as a weak ETag).
//    Real trick: a unique ID per visitor baked into the ETag. Browser revalidates
//    the next visit with If-None-Match -> server reads the ID from the request.
//    Survives cookie deletion (cache persists) and even some incognito windows
//    (Chrome incognito keeps the cache from the session that opened it).
//    NOTE: a same-page double fetch won't send If-None-Match reliably (Chrome's
//    memory cache serves 200), so the honest demonstration is across page loads:
//    the server records every ID it issues, and on a later page load the browser
//    presents the same cached ETag -> the server recognizes it as returning.
const issuedEtagIds = new Set();
app.get("/api/lab/etag", (req, res) => {
  const inMatch = req.headers["if-none-match"] || "";
  const cached = /^W\/"fp-([0-9a-f]+)"/.exec(inMatch);
  let id = cached ? cached[1] : null;
  let isReturning = false;
  if (id) {
    isReturning = issuedEtagIds.has(id);
  } else {
    id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  }
  issuedEtagIds.add(id);
  const firstSeen = !isReturning;

  const body = JSON.stringify({
    etagId: id,
    isReturning,
    ifNoneMatch: inMatch || null,
    note: isReturning
      ? `RE-IDENTIFIED: your browser sent back the ETag "fp-${id}" from its HTTP cache on this second load of the SAME URL. No cookie involved — this ID survives cookie deletion and, in some browsers, incognito.`
      : "First load: we assigned you an ETag ID. Reload the page (or re-run) to see the browser send it back via If-None-Match — that's the supercookie."
  });
  res.status(200);
  res.setHeader("ETag", `W/"fp-${id}"`);
  // Revalidation-friendly: short freshness so the browser actually re-checks with
  // If-None-Match across page loads (a real ETag tracker does this).
  res.setHeader("Cache-Control", "private, max-age=0, must-revalidate");
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Length", Buffer.byteLength(body));
  res.setHeader("X-Accel-Buffering", "no"); // hint proxies not to interfere
  res.end(body); // bypass Express res.json() freshness check (which would 304)
});

// ETag probe is now built into /api/lab/etag itself (same-URL re-fetch).

// 3. Referrer / navigation journey: what the server learns about where you came from.
app.get("/api/lab/referrer", (req, res) => {
  res.json({
    referer: req.headers.referer || null,
    secFetchSite: req.headers["sec-fetch-site"] || null,
    userAgent: req.headers["user-agent"] || null,
    note: "Every navigation sends a Referer header by default (unless Referrer-Policy or an extension strips it). This is how sites know you came from a Google search, a LinkedIn ad, or a newsletter."
  });
});

// 4. The 'correlated profile': what a real tracker assembles from the above.
//    Demonstrates the *linkage* between cookie ID, ETag ID, IP, and fingerprint.
app.get("/api/lab/profile", (req, res) => {
  const cookieId = getCookie(req, "__fp_vid") || null;
  const inMatch = req.headers["if-none-match"] || "";
  const cachedEtag = /^W\/"fp-([0-9a-f]+)"/.exec(inMatch);
  const etagId = cachedEtag ? cachedEtag[1] : null;
  const forwarded = req.headers["x-forwarded-for"] || req.ip || "";
  const ip = forwarded.split(",")[0].trim() || "unknown";

  res.json({
    cookieId,
    etagId,
    ip: ip.split(".").slice(0, 2).join(".") + ".x.x",
    correlates: {
      cookieAndEtagMatch: cookieId ? "independent IDs" : "no cookie yet",
      note: "A tracker stores all of these together: cookie ID, ETag ID, IP, and the client-side fingerprint. Any ONE of them recognizes you later; all of them together make you near-unique."
    }
  });
});

// 5. Storage persistence probe (localStorage / sessionStorage / indexedDB).
//    This is the "storage resurrection" family: IDs stored outside cookies.
app.get("/api/lab/storage", (_req, res) => {
  res.json({
    note: "Client-side storage (localStorage, IndexedDB, Cache API, WebSQL) is a first-party cookie alternative. Sites store an ID there and read it back next visit. Survives 'clear cookies' (many users clear cookies but not site data), survives incognito differently per-browser."
  });
});

// 6. The big one — cross-site identity via the 'referrer + pixel' chain.
//    We can't actually call LinkedIn/Meta from here, but we explain the chain
//    and show the referrer component live.
app.get("/api/lab/pixel", (req, res) => {
  res.json({
    note: "A tracking pixel is just an <img>/<script> to a third party (LinkedIn Insight Tag, Meta Pixel, Google Analytics). The third party sees: referrer (what site you're on), the site's fingerprint of you, your IP, and your User-Agent. If you've EVER logged into that third party on this device, they already have a profile for this device fingerprint.",
    referrerToThirdParty: req.headers.referer || null,
    ip: (req.headers["x-forwarded-for"] || req.ip || "").split(",")[0].trim() || "unknown"
  });
});

app.listen(PORT, () => {
  console.log(`Fingerprint Inspector running at http://localhost:${PORT}`);
});

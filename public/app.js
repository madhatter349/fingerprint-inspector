import { collectAllSignals, combineFingerprint } from "/fingerprint.js?v=4";

const $ = (sel) => document.querySelector(sel);

const statusText = $("#statusText");
const runBtn = $("#runBtn");
const saveBtn = $("#saveBtn");
const historyBtn = $("#historyBtn");
const fpSection = $("#fingerprint");
const fpIdEl = $("#fpId");
const fpNote = $("#fpNote");
const signalsSection = $("#signals");
const signalsGrid = $("#signalsGrid");
const networkSection = $("#network");
const networkBody = $("#networkBody");
const historySection = $("#history");
const historyBody = $("#historyBody");
const compareSection = $("#compare");
const compareBody = $("#compareBody");
const verdictSection = $("#verdict");
const verdictBody = $("#verdictBody");

// Surface any uncaught JS error directly on the page so failures aren't silent.
window.addEventListener("error", (e) => {
  if (statusText) statusText.innerHTML = `<strong style="color:#ff5d5d">JS error:</strong> ${escapeHtml(e.message || String(e))}`;
});
window.addEventListener("unhandledrejection", (e) => {
  if (statusText) statusText.innerHTML = `<strong style="color:#ff5d5d">JS error:</strong> ${escapeHtml(e.reason && e.reason.message ? e.reason.message : String(e.reason))}`;
});

let state = {
  signals: null,
  errors: null,
  fp: null,
  saved: false
};

function setStatus(text, busy) {
  statusText.innerHTML = busy ? `<span class="spinner"></span> ${text}` : text;
}

function tag(text, cls) {
  return `<span class="tag ${cls}">${text}</span>`;
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

function signalCard(name, label, data, tagHtml) {
  return `
    <div class="signal">
      <h3>${label}${tagHtml || ""}</h3>
      <pre>${escapeHtml(pretty(data))}</pre>
    </div>
  `;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

async function runChecks() {
  setStatus("Running fingerprinting battery…", true);
  runBtn.disabled = true;
  saveBtn.disabled = true;

  const t0 = performance.now();
  let result;
  // Watchdog: even if a check hangs, render after 12s with whatever we have.
  const watchdog = new Promise((resolve) => setTimeout(() => resolve({ timedOut: true }), 12000));
  const finished = collectAllSignals().then((r) => ({ ...r, timedOut: false }));
  result = await Promise.race([finished, watchdog]);

  const { results, errors, timedOut } = result;
  const elapsed = Math.round(performance.now() - t0);

  state.signals = results || {};
  state.errors = errors || {};
  state.fp = combineFingerprint(state.signals);
  state.saved = false;

  renderFingerprint();
  renderSignals();
  loadNetworkIdentity();
  renderVerdict();
  setStatus(
    timedOut
      ? `Warning: some checks timed out (${elapsed}ms). Showing partial results below.`
      : `Checks complete in ${elapsed}ms. Click "Save this visit" to store it on the server for comparison.`
  );
  runBtn.disabled = false;
  saveBtn.disabled = false;
  historyBtn.disabled = false;

  // Auto-compare against saved history if any exists.
  compareAgainstHistory();
}

function renderFingerprint() {
  fpSection.hidden = false;
  fpIdEl.textContent = state.fp;
  fpNote.textContent =
    "This is the combined hash of the signals below. If it stays the same across tabs, sessions, and incognito, a site could identify your device without any cookies.";
}

async function loadNetworkIdentity() {
  networkSection.hidden = false;
  networkBody.innerHTML = `<span class="spinner"></span> Loading…`;
  try {
    const res = await fetch("/api/whoami");
    if (!res.ok) throw new Error("status " + res.status);
    const data = await res.json();
    networkBody.innerHTML = `
      <div class="grid">
        <div class="signal">
          <h3>IP address</h3>
          <pre>${escapeHtml(JSON.stringify({ ip: data.ip, coarse: data.ipCoarse, geo: data.geo || null }, null, 2))}</pre>
        </div>
        <div class="signal">
          <h3>Client hints (sent to every server)${Object.keys(data.clientHints || {}).length ? tag("high entropy", "bad") : tag("none sent", "good")}</h3>
          <pre>${escapeHtml(JSON.stringify(data.clientHints, null, 2))}</pre>
        </div>
        <div class="signal">
          <h3>Request headers</h3>
          <pre>${escapeHtml(JSON.stringify(data.headers, null, 2))}</pre>
        </div>
      </div>
      <p class="muted">${escapeHtml(data.ipNote || "")}</p>
      <p class="muted">${escapeHtml(data.clientHintsNote || "")}</p>
    `;
  } catch (e) {
    networkBody.innerHTML = `<p class="muted">Failed to load network identity: ${escapeHtml(e.message)}</p>`;
  }
}

function renderVerdict() {
  const s = state.signals || {};
  const parts = [];
  let bits = 0;

  const counts = {
    audio: s.audio ? 12 : 0,
    canvas: s.canvas ? 8 : 0,
    webgl: s.webgl && s.webgl.unmaskedRenderer ? 14 : s.webgl ? 6 : 0,
    fonts: s.fonts ? Math.min(s.fonts.count || 0, 10) : 0,
    screen: s.screen ? 5 : 0,
    locale: s.locale ? 8 : 0,
    hints: s.clientHints && s.clientHints.highEntropy ? 12 : s.clientHints ? 4 : 0,
    window: s.windowState ? 3 : 0,
    api: s.apiPresence ? 4 : 0,
    connection: s.connection && s.connection.supported ? 2 : 0
  };
  bits = Object.values(counts).reduce((a, b) => a + b, 0);

  if (s.audio && s.audio.hash) parts.push("stable audio fingerprint");
  if (s.canvas && s.canvas.hash) parts.push("stable canvas hash");
  if (s.webgl && s.webgl.unmaskedRenderer) parts.push(`unmasked GPU (${s.webgl.unmaskedRenderer})`);
  else if (s.webgl) parts.push("masked GPU");
  if (s.fonts && s.fonts.count) parts.push(`${s.fonts.count} installed fonts`);
  if (s.locale && s.locale.timezone) parts.push(`timezone ${s.locale.timezone}`);
  if (s.clientHints && s.clientHints.highEntropy && s.clientHints.highEntropy.architecture) parts.push(`CPU ${s.clientHints.highEntropy.architecture}/${s.clientHints.highEntropy.bitness}`);
  if (s.screen && s.screen.colorDepth === 30) parts.push("10-bit display");
  if (s.windowState && s.windowState.devicePixelRatio) parts.push(`DPR ${s.windowState.devicePixelRatio}`);

  const uniqueness = bits >= 40 ? "high" : bits >= 25 ? "moderate" : "low";
  const uniqueTag = uniqueness === "high" ? tag("HIGH — near-unique device ID", "bad") : uniqueness === "moderate" ? tag("MODERATE", "warn") : tag("LOW", "good");

  const verdict = document.createElement("div");
  verdict.innerHTML = `
    <p><strong>Estimated fingerprint entropy:</strong> ~${bits} bits ${uniqueTag}</p>
    <p class="muted">
      Combined, these signals distinguish your device from roughly 1 in ${Math.min(Math.pow(2, bits), 100000000).toLocaleString()}
      browsers. In practice, a tracker seeing all of these can assign you a stable identifier without any cookies.
    </p>
    <h3>How an adversary would turn this into "you"</h3>
    <ol class="muted" style="line-height:1.8">
      <li><strong>Cookie + pixel matching:</strong> You browse site X. Site X runs a LinkedIn/Meta pixel. Your fingerprint (above) is sent to LinkedIn/Meta. If you ever log into LinkedIn/Meta on this device, their server links that fingerprint to your account. From then on, every site running that pixel knows "this visitor = your account".</li>
      <li><strong>Email hashing (id-less matching):</strong> Some sites hash your email and share it with ad networks; the network cross-references your device fingerprint to build a profile.</li>
      <li><strong>IP + ISP correlation:</strong> Even without any matching, your IP + fingerprint can be correlated with account logins from the same IP/subnet, narrowing to a household or device.</li>
      <li><strong>What CAN'T be done:</strong> Reading your LinkedIn cookies, Gmail session, or other sites' storage — all blocked by design in modern browsers.</li>
    </ol>
    <p class="muted">
      <strong>The bottom line:</strong> your device is uniquely fingerprintable (~${bits} bits), but mapping that fingerprint to "Josh Klein" specifically requires ONE cross-reference — logging into an account on this device while a tracking pixel is present. That single event is how the anonymous visitor becomes you.
    </p>
  `;
  verdictSection.hidden = false;
  verdictBody.innerHTML = "";
  verdictBody.appendChild(verdict);
}

function renderSignals() {
  signalsSection.hidden = false;
  const s = state.signals;
  let html = "";

  if (s.audio) {
    const warn = s.audio.zeroGain ? tag("zero-gain silent graph", "warn") : "";
    html += signalCard("audio", "Audio fingerprint (Web Audio)", { ...s.audio, dataURL: undefined }, warn);
  }
  if (s.canvas) {
    html += signalCard("canvas", "Canvas fingerprint", { hash: s.canvas.hash, dataURL: s.canvas.dataURL.slice(0, 60) + "…" }, tag("stable", "bad"));
  }
  if (s.webgl) {
    const extTag = s.webgl.supported ? tag("exposes renderer + extensions", "bad") : "";
    html += signalCard("webgl", "WebGL fingerprint", { renderer: s.webgl.renderer, vendor: s.webgl.vendor, hash: s.webgl.hash, extensions: s.webgl.extensions }, extTag);
  }
  if (s.fonts) {
    const countTag = s.fonts.count > 0 ? tag(`${s.fonts.count} detectable fonts`, "bad") : tag("no detectable fonts", "good");
    html += signalCard("fonts", "Font fingerprint", { count: s.fonts.count, detected: s.fonts.detected, hash: s.fonts.hash }, countTag);
  }
  if (s.webrtc) {
    const leakTag = s.webrtc.ips && s.webrtc.ips.length ? tag("local IPs visible", "bad") : tag("no IP leak detected", "good");
    html += signalCard("webrtc", "WebRTC IP leak", { ips: s.webrtc.ips, hash: s.webrtc.hash, note: s.webrtc.note }, leakTag);
  }
  if (s.screen) {
    html += signalCard("screen", "Screen / display", s.screen, tag("often unique", "warn"));
  }
  if (s.device) {
    html += signalCard("device", "Device / browser", { ...s.device, plugins: s.device.plugins }, tag("reveals hardware + UA", "warn"));
  }
  if (s.storage) {
    html += signalCard("storage", "Storage / cookies", s.storage, "");
  }
  if (s.userAgent) {
    html += signalCard("userAgent", "User agent", s.userAgent, tag("strong identifier", "bad"));
  }
  if (s.linkedin) {
    const tpc = s.linkedin.thirdPartyCookies
      ? tag("3rd-party cookies possible", "bad")
      : tag("3rd-party cookies blocked/absent", "good");
    html += signalCard("linkedin", "LinkedIn session context (local)", { ...s.linkedin, thirdPartyCookiesNote: undefined }, tpc);
  }
  if (s.clientHints) {
    const has = s.clientHints.uaData || s.clientHints.deviceMemory;
    html += signalCard("clientHints", "Client hints", s.clientHints, has ? tag("high entropy", "bad") : tag("minimal", "good"));
  }
  if (s.locale) {
    html += signalCard("locale", "Locale / timezone", s.locale, tag("strong", "warn"));
  }
  if (s.media) {
    html += signalCard("media", "Media features / CSS", s.media, tag("unique-ish", "warn"));
  }
  if (s.connection) {
    const t = s.connection.supported ? tag("reveals network type", "warn") : tag("not exposed", "good");
    html += signalCard("connection", "Network connection", s.connection, t);
  }
  if (s.windowState) {
    html += signalCard("windowState", "Window state", s.windowState, tag("leaks position/size", "warn"));
  }
  if (s.voices) {
    const t = s.voices.count > 0 ? tag(`${s.voices.count} voices`, "warn") : tag("", "");
    html += signalCard("voices", "Speech voices", s.voices, t);
  }
  if (s.apiPresence) {
    html += signalCard("apiPresence", "API surface", { exposed: s.apiPresence.exposed, count: s.apiPresence.count, mediaDevices: s.apiPresence.mediaDevices, webgl: s.apiPresence.webgl }, tag(`${s.apiPresence.count} APIs`, "warn"));
  }
  if (s.loginProbes) {
    html += signalCard("loginProbes", "Login-state probes", s.loginProbes, tag("blocked by design", "good"));
  }

  const errs = Object.keys(state.errors || {});
  if (errs.length) {
    html += `<div class="signal"><h3>Errors</h3><pre>${escapeHtml(pretty(state.errors))}</pre></div>`;
  }

  signalsGrid.innerHTML = html;
}

async function saveVisit() {
  if (!state.fp) return;
  const btn = saveBtn;
  btn.disabled = true;
  const prev = btn.textContent;
  btn.textContent = "Saving…";
  try {
    const res = await fetch("/api/visits", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fingerprint: state.fp,
        signals: state.signals,
        meta: {
          savedAt: new Date().toISOString(),
          userAgent: navigator.userAgent,
          linkedinContext: state.signals.linkedin || null
        }
      })
    });
    if (!res.ok) throw new Error(await res.text());
    state.saved = true;
    setStatus("Visit saved. Open another tab, incognito window, or another browser and save again to compare fingerprints.");
  } catch (e) {
    setStatus("Failed to save: " + e.message);
  } finally {
    btn.textContent = prev;
    btn.disabled = false;
  }
}

async function loadHistory() {
  historySection.hidden = false;
  historyBody.innerHTML = `<span class="spinner"></span> Loading…`;
  try {
    const res = await fetch("/api/visits?limit=200");
    const visits = await res.json();
    if (!visits.length) {
      historyBody.innerHTML = `<p class="muted">No visits yet. Run checks and save a visit to start building history.</p>`;
      return;
    }
    renderHistory(visits);
  } catch (e) {
    historyBody.innerHTML = `<p class="muted">Failed to load: ${escapeHtml(e.message)}</p>`;
  }
}

function renderHistory(visits) {
  const rows = visits.map((v) => {
    const when = new Date(v.ts).toLocaleString();
    const same = state.fp && v.fingerprint === state.fp;
    const ctx = v.meta && v.meta.linkedinContext;
    const ctxLabel = ctx && ctx.incognitoLikely
      ? "incognito"
      : ctx && ctx.thirdPartyCookies
        ? "cookies on"
        : ctx
          ? "cookies off"
          : "";
    return `<tr>
      <td>${escapeHtml(when)}</td>
      <td><code>${escapeHtml(v.fingerprint)}</code></td>
      <td><span class="pill ${same ? "same" : "diff"}">${same ? "SAME" : "DIFF"}</span></td>
      <td><code>${escapeHtml((v.meta && v.meta.userAgent) || "")}</code></td>
      <td>${escapeHtml(ctxLabel)}</td>
    </tr>`;
  }).join("");
  historyBody.innerHTML = `<table><thead><tr><th>Time</th><th>Fingerprint</th><th>vs yours</th><th>User agent</th><th>Context</th></tr></thead><tbody>${rows}</tbody></table>`;
}

async function compareAgainstHistory() {
  if (!state.fp) return;
  compareSection.hidden = false;
  compareBody.innerHTML = `<span class="spinner"></span> Comparing…`;
  try {
    const res = await fetch("/api/compare?self=" + encodeURIComponent(state.fp));
    const data = await res.json();
    if (data.total === 0) {
      compareBody.innerHTML = `<p class="muted">No saved visits yet, so nothing to compare. Save this visit, then open an incognito window (or another browser) and save again.</p>`;
      return;
    }
    const pct = Math.round((data.matches / data.total) * 100);
    const verdict =
      data.matches >= 2
        ? `<p class="muted">Your fingerprint <strong>matches ${data.matches} of ${data.total}</strong> saved visits. A site using this fingerprint could recognize you across those sessions without any cookies.</p>`
        : `<p class="muted">Your fingerprint matches <strong>${data.matches} of ${data.total}</strong> saved visits. More saved visits will make identifiability clearer.</p>`;
    compareBody.innerHTML = verdict + renderHistory(data.visits);
  } catch (e) {
    compareBody.innerHTML = `<p class="muted">Failed to compare: ${escapeHtml(e.message)}</p>`;
  }
}

runBtn.addEventListener("click", runChecks);
saveBtn.addEventListener("click", saveVisit);
historyBtn.addEventListener("click", loadHistory);

// Run once on load.
runChecks();

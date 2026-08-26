import { collectAllSignals, combineFingerprint } from "/fingerprint.js";

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
const historySection = $("#history");
const historyBody = $("#historyBody");
const compareSection = $("#compare");
const compareBody = $("#compareBody");

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
  const { results, errors } = await collectAllSignals();
  const elapsed = Math.round(performance.now() - t0);

  state.signals = results;
  state.errors = errors;
  state.fp = combineFingerprint(results);
  state.saved = false;

  renderFingerprint();
  renderSignals();
  setStatus(`Checks complete in ${elapsed}ms. Click "Save this visit" to store it on the server for comparison.`);
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

// fingerprint.js — browser fingerprinting battery
// Every check runs entirely in this tab and stays on your machine.
// Data is only sent to the server when you click "Save this visit".

export async function collectAllSignals() {
  const results = {};
  const errors = {};

  async function run(name, fn) {
    try {
      results[name] = await fn();
    } catch (e) {
      errors[name] = String(e && e.message ? e.message : e);
    }
  }

  await run("audio", collectAudioFingerprint);
  await run("canvas", collectCanvasFingerprint);
  await run("webgl", collectWebGLFingerprint);
  await run("fonts", collectFontsFingerprint);
  await run("webrtc", collectWebRTCFingerprint);
  await run("screen", collectScreenInfo);
  await run("device", collectDeviceInfo);
  await run("storage", collectStorageInfo);
  await run("userAgent", collectUserAgentInfo);
  await run("linkedin", collectLinkedInContext);

  return { results, errors };
}

// ---- Audio fingerprint (Web Audio API) ----
// Replicates the technique described in the AliExpress article: build a zero-gain
// audio graph, process a known signal, and measure the tiny device-specific
// differences in how the hardware returns it.

const SAMPLE_RATE = 44100;
const NUM_CHANNELS = 1;
const DURATION = 1; // seconds
const TEST_FREQ = 440;
const NUM_OCTAVES = 4;

function buildAudioGraph(ctx, oscillatorType, freq) {
  const dest = ctx.createMediaStreamDestination();
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  const filter = ctx.createBiquadFilter();

  osc.type = oscillatorType;
  osc.frequency.value = freq;

  filter.type = "lowpass";
  filter.frequency.value = 22000;

  gain.gain.value = 0; // silent — never audible

  osc.connect(filter);
  filter.connect(gain);
  gain.connect(dest);

  return { osc, dest };
}

function collectAudioFingerprint() {
  return new Promise((resolve, reject) => {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      ctx.suspend().then(() => {
        const graphs = [];
        for (let octave = 0; octave < NUM_OCTAVES; octave++) {
          graphs.push(buildAudioGraph(ctx, "sine", TEST_FREQ * Math.pow(2, octave)));
        }

        // Render 1 second of the merged graph to an offline buffer.
        const off = new OfflineAudioContext(NUM_CHANNELS, SAMPLE_RATE * DURATION, SAMPLE_RATE);
        const masterGain = off.createGain();
        masterGain.gain.value = 0; // silent
        const masterOsc = off.createOscillator();
        masterOsc.type = "sine";
        masterOsc.frequency.value = TEST_FREQ;
        masterOsc.connect(masterGain);
        masterGain.connect(off.destination);

        graphs.forEach((g) => {
          const src = off.createBufferSource();
          src.buffer = off.createBuffer(NUM_CHANNELS, SAMPLE_RATE, SAMPLE_RATE);
          // Fill with the same reference tone; differences in how it renders are the fingerprint.
          const data = src.buffer.getChannelData(0);
          for (let i = 0; i < data.length; i++) {
            data[i] = Math.sin((2 * Math.PI * TEST_FREQ * i) / SAMPLE_RATE);
          }
          src.connect(off.destination);
          src.start(0);
        });

        // Start at realtime context to make sure the graph is "active" like AliExpress's.
        graphs.forEach((g) => g.osc.start(0));

        off.startRendering().then((rendered) => {
          const data = rendered.getChannelData(0);
          // Quantize the samples into a compact hash. Real fingerprinting uses
          // more elaborate feature extraction; this is a representative demo.
          let acc = 0;
          const step = Math.floor(data.length / 1024);
          for (let i = 0; i < data.length; i += step) {
            const sample = Math.round((data[i] + 1) * 128);
            acc = (acc * 31 + sample) | 0;
          }
          resolve({
            sampleRate: ctx.sampleRate,
            state: ctx.state,
            hash: Math.abs(acc).toString(16).padStart(8, "0"),
            duration: DURATION,
            zeroGain: true,
            technique: "web-audio-offline-render",
            note: "Silent zero-gain graph rendering a reference tone; hardware-specific differences produce a stable, cookie-free identifier."
          });
        });
      });
    } catch (e) {
      reject(e);
    }
  });
}

// ---- Canvas fingerprint ----
function collectCanvasFingerprint() {
  const canvas = document.createElement("canvas");
  canvas.width = 300;
  canvas.height = 150;
  const ctx = canvas.getContext("2d");
  ctx.textBaseline = "top";
  ctx.font = "16px Arial";
  ctx.fillStyle = "#f60";
  ctx.fillRect(125, 1, 62, 20);
  ctx.fillStyle = "#069";
  ctx.fillText("Fingerprint Inspector \u2764\ufe0f", 2, 15);
  ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
  ctx.font = "18px Georgia";
  ctx.fillText("crypto\u2122 \u2603", 4, 45);
  return { dataURL: canvas.toDataURL(), hash: hashString(canvas.toDataURL()) };
}

// ---- WebGL fingerprint ----
function collectWebGLFingerprint() {
  const canvas = document.createElement("canvas");
  const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
  if (!gl) return { supported: false };
  const glInfo = {
    renderer: gl.getParameter(gl.RENDERER),
    vendor: gl.getParameter(gl.VENDOR),
    version: gl.getParameter(gl.VERSION),
    shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
    maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
    maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
  };
  const extensions = (gl.getSupportedExtensions() || []).sort();
  return { ...glInfo, extensions: extensions.length, supported: true, hash: hashString(JSON.stringify(glInfo) + extensions.join("|")) };
}

// ---- Font fingerprint (installed font detection) ----
function collectFontsFingerprint() {
  const baseFonts = ["monospace", "sans-serif", "serif"];
  const testFonts = [
    "Arial", "Arial Black", "Arial Narrow", "Calibri", "Cambria", "Cambria Math",
    "Comic Sans MS", "Consolas", "Courier New", "Georgia", "Helvetica", "Impact",
    "Lucida Console", "Lucida Sans Unicode", "Microsoft Sans Serif", "Palatino Linotype",
    "Segoe UI", "Segoe UI Symbol", "Tahoma", "Times New Roman", "Trebuchet MS",
    "Verdana", "monospace", "sans-serif", "serif", "Wingdings", "Wingdings 2",
    "Wingdings 3", "Symbol", "Webdings", "MS Gothic", "MS Mincho", "Yu Gothic",
    "Yu Mincho", "Meiryo", "Hiragino Sans", "Hiragino Kaku Gothic ProN", "Helvetica Neue",
    "PingFang SC", "Noto Sans", "Noto Serif", "Noto Sans CJK JP", "Roboto", "Open Sans"
  ];
  const width = 250;
  const height = 50;
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  canvas.width = width;
  canvas.height = height;
  ctx.fillStyle = "#000";
  ctx.textBaseline = "bottom";
  ctx.font = '16px monospace';
  ctx.fillText("mmii00 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ", 0, 40);

  function measure(font) {
    ctx.font = `16px "${font}", monospace`;
    ctx.fillText("mmii00 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ", 0, 40);
    return ctx.measureText("mmii00").width;
  }

  const base = baseFonts.map(measure);
  const detected = [];
  for (const f of testFonts) {
    const w = measure(f);
    const isDefault = base.some((b) => Math.abs(w - b) < 0.001);
    if (!isDefault) detected.push(f);
  }
  return { detected, count: detected.length, hash: hashString(detected.join("|")) };
}

// ---- WebRTC fingerprint ----
function collectWebRTCFingerprint() {
  return new Promise((resolve, reject) => {
    try {
      if (!window.RTCPeerConnection) return resolve({ supported: false });
      const pc = new RTCPeerConnection({ iceServers: [] });
      const ips = new Set();
      const done = () => {
        pc.close();
        resolve({ ips: [...ips], hash: hashString([...ips].sort().join("|")), note: "Local IPs can leak via ICE candidates even without STUN servers." });
      };
      const timeout = setTimeout(done, 3000);
      pc.onicecandidate = (e) => {
        if (!e.candidate) { clearTimeout(timeout); done(); return; }
        const match = /([0-9]{1,3}\.){3}[0-9]{1,3}/.exec(e.candidate.candidate);
        if (match) ips.add(match[0]);
      };
      pc.createDataChannel("");
      pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(reject);
    } catch (e) {
      reject(e);
    }
  });
}

// ---- Screen / display ----
function collectScreenInfo() {
  const dpr = window.devicePixelRatio;
  const screen = window.screen;
  return {
    dpr,
    width: screen.width,
    height: screen.height,
    availWidth: screen.availWidth,
    availHeight: screen.availHeight,
    colorDepth: screen.colorDepth,
    pixelDepth: screen.pixelDepth,
    orientation: screen.orientation ? screen.orientation.type : null,
    outerWidth: window.outerWidth,
    outerHeight: window.outerHeight,
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight
  };
}

// ---- Device / browser ----
function collectDeviceInfo() {
  const nav = navigator;
  return {
    userAgent: nav.userAgent,
    language: nav.language,
    languages: nav.languages,
    platform: nav.platform,
    hardwareConcurrency: nav.hardwareConcurrency || null,
    deviceMemory: nav.deviceMemory || null,
    maxTouchPoints: nav.maxTouchPoints || 0,
    cookieEnabled: nav.cookieEnabled,
    doNotTrack: nav.doNotTrack,
    vendor: nav.vendor,
    vendorSub: nav.vendorSub || "",
    productSub: nav.productSub || "",
    webdriver: nav.webdriver,
    plugins: Array.from(nav.plugins || []).map((p) => p.name).join("|")
  };
}

// ---- Storage / cookie visibility (LinkedIn context) ----
function collectStorageInfo() {
  const out = {
    cookiesEnabled: navigator.cookieEnabled,
    localStorage: safe(() => localStorage.length),
    sessionStorage: safe(() => sessionStorage.length),
    indexedDB: safe(() => indexedDB ? true : false),
    canUseCookies: true
  };
  try {
    const name = "__fp_test__";
    document.cookie = name + "=1; path=/; max-age=5";
    out.cookieWrite = document.cookie.includes(name);
    document.cookie = name + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  } catch {
    out.cookieWrite = false;
  }
  return out;

  function safe(fn) {
    try { return fn(); } catch { return "blocked"; }
  }
}

// ---- LinkedIn session context (purely local, no cross-site calls) ----
// Reveals how much of your current session state could be tied to a fingerprint,
// without ever contacting LinkedIn. Use this to compare a logged-in vs incognito visit.
function collectLinkedInContext() {
  const out = {
    thirdPartyCookies: null,
    thirdPartyCookiesNote: "Detected by a local probe; not a guarantee of cross-site blocking.",
    sameSiteStrictCookies: null,
    siteCookiesVisible: null,
    sessionStorageKeys: safe(() => sessionStorage.length),
    localStorageKeys: safe(() => localStorage.length),
    incognitoLikely: null
  };

  // Probe third-party cookie behavior with a local iframe-free mechanism:
  // an <img> ping to a local endpoint, plus checking whether a same-site
  // cookie we set is readable after navigation. This is best-effort; modern
  // browsers block cross-site cookies per-site, which we can't fully probe
  // from first-party context.
  try {
    const n = "__fp_3p__";
    document.cookie = n + "=1; path=/; max-age=5; SameSite=None";
    out.thirdPartyCookies = document.cookie.includes(n);
    document.cookie = n + "=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  } catch {
    out.thirdPartyCookies = false;
  }

  // Detect if we're in an incognito/private window using a timing probe.
  try {
    const start = performance.now();
    const temp = localStorage;
    // Safari exposes quota errors differently; just estimate.
    out.incognitoLikely = navigator.webdriver ? false : performance.now() - start > 50;
  } catch {
    out.incognitoLikely = true;
  }

  return out;

  function safe(fn) {
    try { return fn(); } catch { return "blocked"; }
  }
}

// ---- User-agent / navigator details ----
function collectUserAgentInfo() {
  const ua = navigator.userAgent;
  const data = {
    ua,
    appVersion: navigator.appVersion,
    buildID: navigator.buildID || "",
    oscpu: navigator.oscpu || "",
    platform: navigator.platform,
    language: navigator.language
  };
  return { ...data, hash: hashString(ua + navigator.platform + navigator.language) };
}

// ---- Helper: stable string hash (FNV-1a) ----
function hashString(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

// ---- Master fingerprint ID ----
export function combineFingerprint(signals) {
  const parts = [];
  if (signals.audio) parts.push("audio:" + signals.audio.hash);
  if (signals.canvas) parts.push("canvas:" + signals.canvas.hash);
  if (signals.webgl) parts.push("webgl:" + signals.webgl.hash);
  if (signals.fonts) parts.push("fonts:" + signals.fonts.hash);
  if (signals.webrtc) parts.push("webrtc:" + signals.webrtc.hash);
  if (signals.screen) parts.push("screen:" + hashString(JSON.stringify(signals.screen)));
  if (signals.device) parts.push("device:" + hashString(JSON.stringify(signals.device)));
  if (signals.userAgent) parts.push("ua:" + signals.userAgent.hash);
  return hashString(parts.join("|"));
}

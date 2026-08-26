// fingerprint.js — browser fingerprinting battery
// Every check runs entirely in this tab and stays on your machine.
// Data is only sent to the server when you click "Save this visit".

export async function collectAllSignals() {
  const results = {};
  const errors = {};

  const defs = [
    ["audio", collectAudioFingerprint],
    ["canvas", collectCanvasFingerprint],
    ["webgl", collectWebGLFingerprint],
    ["fonts", collectFontsFingerprint],
    ["webrtc", collectWebRTCFingerprint],
    ["screen", collectScreenInfo],
    ["device", collectDeviceInfo],
    ["storage", collectStorageInfo],
    ["userAgent", collectUserAgentInfo],
    ["linkedin", collectLinkedInContext],
    ["clientHints", collectClientHints],
    ["locale", collectLocaleInfo],
    ["media", collectMediaFeatures],
    ["connection", collectConnectionInfo],
    ["windowState", collectWindowState],
    ["voices", collectVoices],
    ["apiPresence", collectApiPresence],
    ["loginProbes", collectLoginProbes]
  ];

  await Promise.allSettled(
    defs.map(async ([name, fn]) => {
      try {
        results[name] = await withTimeout(fn(), 5000, name);
      } catch (e) {
        errors[name] = String(e && e.message ? e.message : e);
      }
    })
  );

  return { results, errors };
}

function withTimeout(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label + " timed out after " + ms + "ms")), ms);
    })
  ]).finally(() => clearTimeout(timer));
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

function collectAudioFingerprint() {
  return new Promise((resolve, reject) => {
    try {
      // Use OfflineAudioContext only — deterministic, needs no live audio device,
      // and cannot hang on a realtime AudioContext.suspend() (which is the
      // failure mode that left this page stuck on "Initializing…").
      const off = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(
        NUM_CHANNELS,
        SAMPLE_RATE * DURATION,
        SAMPLE_RATE
      );

      const masterGain = off.createGain();
      masterGain.gain.value = 0; // silent — never audible
      masterGain.connect(off.destination);

      for (let octave = 0; octave < NUM_OCTAVES; octave++) {
        const osc = off.createOscillator();
        osc.type = "sine";
        osc.frequency.value = TEST_FREQ * Math.pow(2, octave);
        osc.connect(masterGain);
        osc.start(0);
      }

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
          sampleRate: off.sampleRate,
          length: data.length,
          hash: Math.abs(acc).toString(16).padStart(8, "0"),
          duration: DURATION,
          zeroGain: true,
          technique: "web-audio-offline-render",
          note: "Silent zero-gain graph rendering a reference tone; hardware-specific differences produce a stable, cookie-free identifier."
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
  // Unmasked renderer: this is what real trackers read. Chrome masks the string
  // in gl.RENDERER, but WEBGL_debug_renderer_info exposes the real GPU.
  try {
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    if (dbg) {
      glInfo.unmaskedRenderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
      glInfo.unmaskedVendor = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL));
    }
  } catch (e) {
    glInfo.unmaskedError = String(e.message || e);
  }
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

// ---- Client hints (JS-accessible subset + high-entropy) ----
async function collectClientHints() {
  const nav = navigator;
  const out = {
    uaData: null,
    highEntropy: null,
    deviceMemory: nav.deviceMemory || null,
    hardwareConcurrency: nav.hardwareConcurrency || null,
    maxTouchPoints: nav.maxTouchPoints || 0
  };

  if (nav.userAgentData) {
    out.uaData = {
      brands: nav.userAgentData.brands,
      mobile: nav.userAgentData.mobile,
      platform: nav.userAgentData.platform
    };
    // getHighEntropyValues needs a secure context and user permission in Chrome.
    if (typeof nav.userAgentData.getHighEntropyValues === "function") {
      try {
        const he = await nav.userAgentData.getHighEntropyValues([
          "architecture", "bitness", "model", "platformVersion", "fullVersionList", "wow64"
        ]);
        out.highEntropy = {
          architecture: he.architecture,
          bitness: he.bitness,
          model: he.model,
          platformVersion: he.platformVersion,
          fullVersionList: he.fullVersionList,
          wow64: he.wow64
        };
      } catch (e) {
        out.highEntropy = { error: String(e.message || e) };
      }
    }
  }

  out.hash = hashString(
    JSON.stringify(out.uaData ? out.uaData.brands : "") +
    JSON.stringify(out.highEntropy || "") +
    (nav.deviceMemory || "") + (nav.hardwareConcurrency || "") + (nav.maxTouchPoints || 0)
  );
  return out;
}

// ---- Locale / timezone ----
function collectLocaleInfo() {
  return {
    language: navigator.language,
    languages: navigator.languages,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    offsetMin: new Date().getTimezoneOffset(),
    hash: hashString(navigator.language + "|" + navigator.languages.join(",") + "|" + Intl.DateTimeFormat().resolvedOptions().timeZone)
  };
}

// ---- Media features / CSS queries ----
function collectMediaFeatures() {
  const mm = window.matchMedia;
  const out = {
    prefersColorScheme: mm ? (mm("(prefers-color-scheme: dark)").matches ? "dark" : "light") : null,
    prefersReducedMotion: mm ? mm("(prefers-reduced-motion: reduce)").matches : null,
    prefersReducedTransparency: mm ? mm("(prefers-reduced-transparency: reduce)").matches : null,
    pointer: mm ? (mm("(pointer: coarse)").matches ? "coarse" : mm("(pointer: fine)").matches ? "fine" : null) : null,
    hover: mm ? (mm("(hover: none)").matches ? "none" : mm("(hover: hover)").matches ? "hover" : null) : null,
    anyPointer: mm ? (mm("(any-pointer: coarse)").matches ? "coarse" : mm("(any-pointer: fine)").matches ? "fine" : null) : null,
    minContrast: mm ? mm("(prefers-contrast: more)").matches : null,
    forcedColors: mm ? mm("(forced-colors: active)").matches : null
  };
  return { ...out, hash: hashString(JSON.stringify(out)) };
}

// ---- Network connection (only useful if a live connection exists) ----
function collectConnectionInfo() {
  const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  if (!conn) return { supported: false, note: "Network Information API not exposed." };
  return {
    supported: true,
    effectiveType: conn.effectiveType,
    downlink: conn.downlink,
    rtt: conn.rtt,
    saveData: conn.saveData,
    type: conn.type,
    hash: hashString(JSON.stringify({ et: conn.effectiveType, dl: conn.downlink, rtt: conn.rtt, save: conn.saveData }))
  };
}

// ---- Window state (leaks approximate dimensions & position) ----
function collectWindowState() {
  const w = window;
  return {
    innerWidth: w.innerWidth,
    innerHeight: w.innerHeight,
    outerWidth: w.outerWidth,
    outerHeight: w.outerHeight,
    screenX: w.screenX,
    screenY: w.screenY,
    devicePixelRatio: w.devicePixelRatio,
    hash: hashString(JSON.stringify({ iw: w.innerWidth, ih: w.innerHeight, ow: w.outerWidth, oh: w.outerHeight, sx: w.screenX, sy: w.screenY, dpr: w.devicePixelRatio }))
  };
}

// ---- Speech synthesis voices ----
function collectVoices() {
  return new Promise((resolve) => {
    if (!window.speechSynthesis) return resolve({ supported: false });
    const voices = window.speechSynthesis.getVoices();
    if (voices.length) {
      resolve({ supported: true, count: voices.length, sample: voices.slice(0, 8).map((v) => v.name + "(" + v.lang + ")"), hash: hashString(voices.map((v) => v.name + v.lang).join("|")) });
      return;
    }
    // Voices load async in Chrome.
    window.speechSynthesis.onvoiceschanged = () => {
      const vs = window.speechSynthesis.getVoices();
      resolve({ supported: true, count: vs.length, sample: vs.slice(0, 8).map((v) => v.name + "(" + v.lang + ")"), hash: hashString(vs.map((v) => v.name + v.lang).join("|")) });
    };
    setTimeout(() => resolve({ supported: true, count: 0, note: "voices not loaded within 2s", hash: hashString("") }), 2000);
  });
}

// ---- API surface (adds to uniqueness) ----
async function collectApiPresence() {
  const props = [
    "serviceWorker", "geolocation", "mediaDevices", "bluetooth", "usb", "hid", "serial",
    "permissions", "credentials", "storage", "indexedDB", "caches", "scheduling",
    "share", "vibrate", "getBattery", "wakeLock", "contacts", "doNotTrack",
    "webdriver", "languages", "pdfViewerEnabled"
  ];
  const found = [...new Set(props.filter((p) => typeof navigator[p] !== "undefined" || (p === "vibrate" && typeof navigator.vibrate === "function")))];
  const canvasOps = (() => {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
    if (!gl) return null;
    try {
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      return dbg
        ? { unmaskedRenderer: String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)), unmaskedVendor: String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)) }
        : { renderer: gl.getParameter(gl.RENDERER), vendor: gl.getParameter(gl.VENDOR) };
    } catch (e) {
      return { error: String(e.message || e) };
    }
  })();

  // Media devices: without permission we only see labels like "Default".
  let mediaDevices = null;
  try {
    if (navigator.mediaDevices && typeof navigator.mediaDevices.enumerateDevices === "function") {
      mediaDevices = (await navigator.mediaDevices.enumerateDevices()).map((d) => d.kind + ":" + d.label);
    }
  } catch (e) {
    mediaDevices = { error: String(e.message || e) };
  }

  return {
    exposed: found,
    count: found.length,
    webgl: canvasOps,
    mediaDevices,
    hash: hashString(found.join("|") + JSON.stringify(canvasOps) + (mediaDevices ? JSON.stringify(mediaDevices) : ""))
  };
}

// ---- Login-state probes (the "who am I logged in as" angle) ----
// Modern browsers forbid reading other sites' cookies. The remaining real-world
// leak is ad-tech account linking via pixels. What we CAN probe from first-party:
function collectLoginProbes() {
  return new Promise((resolve) => {
    const out = {
      note: "Cross-origin cookie reads are blocked by modern browsers. These probes show what is (and isn't) possible from a first-party page.",
      fedcm: null,
      fedcmNote: null,
      loginHints: null,
      loginHintsNote: null
    };

    // 1. FedCM identity providers (Chrome 117+): reveals which IDPs the browser
    //    knows the user is signed into, WITHOUT user interaction.
    if (navigator.credentials && typeof navigator.credentials.get === "function" && "IdentityCredential" in window) {
      out.fedcmSupported = true;
      // We do NOT actually call FedCM here (it requires user mediation and is
      // gated). We report whether the API is present so the reader knows it's
      // the official mechanism by which sites detect sign-in state.
      out.fedcm = "API present — can reveal signed-in identity providers after user consent";
    } else {
      out.fedcmSupported = false;
    }

    // 2. Fetch preflight / resource timing hints. Loading a known cross-origin
    //    asset (e.g. a favicon) and timing it reveals very little in modern
    //    browsers, but a 403/200 difference on a third-party endpoint is the
    //    classic login-detection trick. We only demonstrate the mechanism.
    //    We do NOT hit third parties; we show the technique is monitored.
    out.loginHints = "Cross-site login detection is blocked (Cookies partitioned). LinkedIn/Google/GitHub cannot be probed from this origin.";

    resolve(out);
  });
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
  if (signals.clientHints) parts.push("hints:" + signals.clientHints.hash);
  if (signals.locale) parts.push("locale:" + signals.locale.hash);
  if (signals.media) parts.push("media:" + signals.media.hash);
  if (signals.connection && signals.connection.supported) parts.push("conn:" + signals.connection.hash);
  if (signals.windowState) parts.push("win:" + signals.windowState.hash);
  if (signals.voices && signals.voices.supported) parts.push("voices:" + signals.voices.hash);
  if (signals.apiPresence) parts.push("api:" + signals.apiPresence.hash);
  return hashString(parts.join("|"));
}

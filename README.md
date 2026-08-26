# Fingerprint Inspector

Inspect your own browser's fingerprinting surface — the same kind of signals sites like AliExpress use for silent, cookie-free tracking.

## What it does

- Runs a full fingerprinting battery **entirely in your browser tab**:
  - **Audio fingerprinting** (Web Audio API, zero-gain silent graph — the AliExpress technique)
  - Canvas, WebGL, font detection, WebRTC IP leak, screen/display, device/browser details, storage/cookie visibility
  - **LinkedIn session context**: a purely-local probe showing whether your current session's cookie state could be tied to a fingerprint
- Computes a combined fingerprint ID and shows each signal's contribution
- Saves visits to a small backend so you can compare fingerprints across:
  - Normal tab vs incognito
  - Different browsers
  - Logged-in (LinkedIn) vs not
- Shows which saved visits share your fingerprint (identifiability across sessions)

## Run locally

```bash
npm install
npm start
```

Then open http://localhost:3000

## How to use the comparison feature

1. Open the page in your normal Chrome profile (logged into LinkedIn) and click **Save this visit**.
2. Open the same page in an incognito window (not logged in) and **Save this visit** again.
3. Open the visit history / comparison view. If the fingerprint is **SAME**, a site could recognize you across those contexts without cookies. If **DIFF**, something about your incognito session differs.

## Privacy notes

- All fingerprint checks run in your browser. No third-party trackers are loaded.
- Data is only sent to this server when you click **Save this visit**.
- The comparison is only meaningful between visits saved to the same server instance.
- On Railway, visit data is stored in a plain JSON file (`.data/visits.json`) on the service's local disk — ephemeral, per-instance, and not shared across instances.

## Deploying to Railway

This app reads `PORT` from the environment. Just connect this repo to Railway and deploy with the default Node.js buildpack (`npm install` + `npm start`). No extra configuration required.

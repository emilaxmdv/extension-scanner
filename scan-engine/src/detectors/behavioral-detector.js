/**
 * Scan Engine — Behavioral Detector
 * AST + regex pattern detection for suspicious code behaviour
 * v3 adds: fingerprinting, crypto-mining, WASM, sendBeacon, shadow DOM, iframes
 */

import { parse } from 'acorn';
import { simple as walk } from 'acorn-walk';
import { BEHAVIORAL_WEIGHTS } from '../constants.js';
import { isExternalUrl, extractBase64Strings } from '../utils/helpers.js';

/**
 * Analyse JS files for behavioural indicators
 */
export function detectBehavioralIndicators(jsFiles) {
  if (!jsFiles || jsFiles.length === 0) {
    return { score: 0, indicators: [], details: {}, summary: [] };
  }

  const merged = new Map();
  const details = {};

  for (const file of jsFiles) {
    const fi = analyzeFile(file.content, file.name);
    for (const [type, count] of Object.entries(fi)) {
      merged.set(type, (merged.get(type) || 0) + count);
      if (count > 0) {
        if (!details[type]) details[type] = [];
        details[type].push({ file: file.name, count });
      }
    }
  }

  let total = 0;
  const indicators = [];
  for (const [type, count] of merged.entries()) {
    if (count > 0) {
      const weight = BEHAVIORAL_WEIGHTS[type] || 0;
      const contrib = Math.min(weight * Math.log2(count + 1), weight * 2);
      total += contrib;
      indicators.push({ type, count, weight, score: Math.round(contrib) });
    }
  }

  return {
    score: Math.round(total),
    indicators,
    details,
    summary: buildSummary(indicators),
  };
}

// ─── Single-file analysis ────────────────────────────────────
function analyzeFile(code, filename) {
  const I = {};
  // initialise every known indicator to 0
  for (const key of Object.keys(BEHAVIORAL_WEIGHTS)) I[key] = 0;

  // ── Regex-based detection ──
  const rx = (pattern) => (code.match(pattern) || []).length;

  I.EVAL_USAGE          = rx(/\beval\s*\(/g);
  I.DOCUMENT_COOKIE     = rx(/document\.cookie/g);
  I.ATOB_USAGE          = rx(/\batob\s*\(/g);
  I.BTOA_USAGE          = rx(/\bbtoa\s*\(/g);
  I.DOCUMENT_WRITE      = rx(/document\.write(ln)?\s*\(/g);
  I.CHROME_COOKIES_API  = rx(/chrome\.cookies/g);
  I.WEBREQUEST_API      = rx(/chrome\.webRequest/g);
  I.WEBREQUEST_BLOCKING = rx(/chrome\.webRequest\.onBeforeRequest/g);
  I.CHROME_TABS_EXECUTE = rx(/chrome\.tabs\.executeScript/g);
  I.CHROME_SCRIPTING_EXECUTE = rx(/chrome\.scripting\.executeScript/g);
  I.LOCAL_STORAGE_ACCESS = rx(/localStorage\./g);
  I.INDEXED_DB_ACCESS   = rx(/indexedDB\.open/g);
  I.SENDBEACON          = rx(/navigator\.sendBeacon\s*\(/g);
  I.WASM_INSTANTIATE    = rx(/WebAssembly\.(instantiate|compile)/g);
  I.CLIPBOARD_READ_API  = rx(/navigator\.clipboard\.read/g);
  I.CLIPBOARD_WRITE_API = rx(/navigator\.clipboard\.write/g);
  I.TEXT_ENCODER_DECODER = rx(/new\s+Text(Encoder|Decoder)\s*\(/g);
  I.SUBTLE_CRYPTO       = rx(/crypto\.subtle\./g);

  // Fingerprinting
  I.CANVAS_FINGERPRINT  = rx(/\.toDataURL\s*\(|\.getImageData\s*\(/g);
  I.WEBGL_FINGERPRINT   = rx(/getParameter\s*\(\s*(debugInfo|renderer|vendor)/g)
                        + rx(/WEBGL_debug_renderer_info/g);
  I.AUDIO_FINGERPRINT   = rx(/createOscillator|createAnalyser|OfflineAudioContext/g);
  I.FONT_ENUMERATION    = rx(/document\.fonts\.(check|forEach)|queryLocalFonts/g);
  I.SCREEN_ENUMERATION  = rx(/screen\.(width|height|colorDepth|pixelDepth)/g);
  I.NAVIGATOR_PROPERTIES = rx(/navigator\.(hardwareConcurrency|deviceMemory|platform|userAgentData)/g);

  // Crypto-mining heuristics
  I.CRYPTO_MINING_PATTERN = rx(/CoinHive|coinhive|cryptonight|stratum\+tcp/gi)
                          + rx(/hashRate|nonce.*increment|mining.*pool/gi);

  // Shadow DOM (closed)
  I.SHADOW_DOM_CLOSED   = rx(/attachShadow\s*\(\s*\{[^}]*mode\s*:\s*['"]closed['"]/g);

  // Base64 large blobs
  const b64 = extractBase64Strings(code);
  I.BASE64_LARGE = b64.filter(s => s.length > 500).length;

  // ── AST-based detection ──
  try {
    const ast = parse(code, { ecmaVersion: 'latest', sourceType: 'module', locations: false });
    walk(ast, {
      NewExpression(node) {
        const name = node.callee.name;
        if (name === 'Function') I.FUNCTION_CONSTRUCTOR++;
        if (name === 'WebSocket') I.WEBSOCKET_CONNECTION++;
        if (name === 'XMLHttpRequest') I.XMLHTTPREQUEST_EXTERNAL++;
      },
      ImportExpression() { I.DYNAMIC_IMPORT++; },
      CallExpression(node) {
        // fetch to external
        if (node.callee.name === 'fetch' && node.arguments.length > 0) {
          const arg = node.arguments[0];
          if (arg.type === 'Literal' && typeof arg.value === 'string' && isExternalUrl(arg.value)) {
            I.EXTERNAL_FETCH++;
          } else if (arg.type === 'TemplateLiteral') {
            const raw = arg.quasis.map(q => q.value.raw).join('');
            if (isExternalUrl(raw)) I.EXTERNAL_FETCH++;
          }
        }
        // createElement('script') / createElement('iframe')
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.property.name === 'createElement' &&
          node.arguments.length > 0 &&
          node.arguments[0].type === 'Literal'
        ) {
          const tag = (node.arguments[0].value || '').toLowerCase();
          if (tag === 'script') I.SCRIPT_INJECTION++;
          if (tag === 'iframe') I.IFRAME_CREATION++;
        }
        // form.submit to external
        if (
          node.callee.type === 'MemberExpression' &&
          node.callee.property.name === 'submit'
        ) {
          I.FORM_SUBMIT_EXTERNAL++;
        }
      },
      AssignmentExpression(node) {
        if (node.left.type === 'MemberExpression' && node.left.property.name === 'innerHTML') {
          I.INNERHTML_ASSIGNMENT++;
        }
      },
    });
  } catch {
    // AST failed — rely on regex results only
  }

  return I;
}

// ─── Summary builder ─────────────────────────────────────────
function buildSummary(indicators) {
  const s = [];
  const crit = indicators.filter(i => i.weight >= 15);
  const high = indicators.filter(i => i.weight >= 10 && i.weight < 15);
  if (crit.length) s.push(`${crit.length} critical behavioural pattern(s) detected`);
  if (high.length) s.push(`${high.length} high-risk behavioural pattern(s) detected`);

  const find = (t) => indicators.find(i => i.type === t);
  const ev = find('EVAL_USAGE');
  if (ev) s.push(`eval() used ${ev.count} time(s)`);
  const ext = find('EXTERNAL_FETCH');
  if (ext) s.push(`${ext.count} external network request(s)`);
  const fp = indicators.filter(i => ['CANVAS_FINGERPRINT','WEBGL_FINGERPRINT','AUDIO_FINGERPRINT','FONT_ENUMERATION'].includes(i.type));
  if (fp.length) s.push(`${fp.length} browser-fingerprinting technique(s)`);
  const mine = find('CRYPTO_MINING_PATTERN');
  if (mine) s.push('Possible crypto-mining code detected');
  return s;
}
